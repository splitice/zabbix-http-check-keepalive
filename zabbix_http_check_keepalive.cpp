#include <sys/epoll.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <map>
#include <errno.h>
#include <time.h>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <signal.h>
#include <stdlib.h>
#include <netdb.h>
#include <functional>
#include <functional>
#include <cstring>
#include "sysinc.h"
#include "module.h"

extern "C" {
	#include "common.h"
	int    zbx_module_hck_check(AGENT_REQUEST *request, AGENT_RESULT *result);
}

static ZBX_METRIC keys[] =
/* KEY               FLAG           FUNCTION                TEST PARAMETERS */
{
	{ "hck.check", CF_HAVEPARAMS, (int(*)())zbx_module_hck_check, "203.13.161.80,80" },
	{ NULL }
};

const char http_request[] = "HEAD / HTTP/1.0\r\nConnection:Keep-Alive\r\n\r\n";
#define http_request_size (sizeof(http_request) - 1)
int http_resp_startlen = sizeof("HTTP/1.0 ");//or "HTTP 1.1" same length

#define READSIZE 1024
#define MAXEVENTS 16
#define TIMEOUT_RECOVER 3
#define TIMEOUT_NEW 4
#define TIMEOUT_POST 60

const char *socket_path = "\0hck";
volatile int running = 1;

using namespace std;

struct cmp_map {
	bool operator()(
		const struct sockaddr& lhs,
		const struct sockaddr& rhs) const
	{
		return std::memcmp(&lhs, &rhs, sizeof(lhs));
	}
};

// a check
struct hck_details {
	time_t expires;
	int client_socket;
	int remote_socket;
	struct sockaddr remote_connection;
	unsigned int remote_connection_len : 8;
	unsigned short position : 16;
	enum {
		connecting,
		writing,
		reading,
		keepalive,
		recovery
	} state: 6;
	bool first : 1;
	bool tfo : 1;
};

// the hck system (could be exported outside of zabbix in future)
class hck_handle {
public:
	int epfd;
	map<int, struct hck_details*> sockets;
	map<struct sockaddr, int, struct cmp_map> keepalived;
};

//send result from worker -> process
bool send_result(hck_handle* hck, int sock, unsigned short result){
	//Communication socket failed!
	if (sock == -1) {
		return true;
	}

	// Actually send result
	int rc = send(sock, &result, sizeof(result), 0);
	return rc >= 0;
}

static hck_details* keepalive_lookup(hck_handle* hck, unsigned int sockaddr_len,  struct sockaddr sockaddr, time_t now, int source) {
	map<struct sockaddr, int>::iterator it;

	it = hck->keepalived.find(sockaddr);
	if (it != hck->keepalived.end()) {
		struct hck_details* h = hck->sockets[it->second];
		hck->keepalived.erase(it->first);

		//Err, it should be....
		if (h->state == hck_details::keepalive) {
			h->state = hck_details::recovery;
			h->position = 0;
			h->expires = now + TIMEOUT_RECOVER;
			h->client_socket = source;
			assert(h->remote_connection_len == sockaddr_len);
			h->first = false;
			h->tfo = true;
			return h;
		}
	}

	return NULL;
}

static struct hck_details* create_new_socket(hck_handle* hck, unsigned int sockaddr_len, struct sockaddr sockaddr, time_t now, int source, bool fastopen = true) {
	struct hck_details* h = new struct hck_details;
	int socket_desc;
	struct epoll_event e;
	int rc;

	//Create socket
	socket_desc = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (socket_desc == -1)
	{
		perror("error creating remote socket");
		close(h->client_socket);
		delete h;
		return NULL;
	}

	//Connect to remote server
#ifdef MSG_FASTOPEN
	if (fastopen)
	{
		rc = sendto(socket_desc, http_request, http_request_size, MSG_FASTOPEN, &sockaddr, sockaddr_len);
	}
	else
	{
		rc = connect(socket_desc, &sockaddr, sockaddr_len);
	}
#else
	rc = connect(socket_desc, &sockaddr, sockaddr_len);
#endif
	if (rc < 0)
	{
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINPROGRESS) {
			perror("error connecting");
			close(socket_desc);
			close(h->client_socket);
			delete h;
			return NULL;
		}


#ifdef MSG_FASTOPEN
		e.events = EPOLLOUT;
		h->state = hck_details::writing;
		h->position = 0;
#else
		e.events = EPOLLIN | EPOLLOUT;
		h->state = hck_details::connecting;
#endif
	}
	else
	{
#ifdef MSG_FASTOPEN
		if (rc < http_request_size) {
			e.events = EPOLLOUT;
			h->state = hck_details::writing;
			h->position = rc;
		}
		else {
			e.events = EPOLLIN;
			h->state = hck_details::reading;
			h->position = 0;
		}
#else
		e.events = EPOLLOUT;
		h->state = hck_details::writing;
		h->position = 0;
#endif
	}
	e.data.fd = socket_desc;
	rc = epoll_ctl(hck->epfd, EPOLL_CTL_ADD, socket_desc, &e);
	if (rc < 0)
	{
		perror("epoll add error");
		close(socket_desc);
		close(h->client_socket);
		delete h;
		return NULL;
	}

	h->expires = now + TIMEOUT_NEW;
	h->client_socket = source;
	h->remote_connection = sockaddr;
	h->remote_connection_len = sockaddr_len;
	h->remote_socket = socket_desc;
	h->first = true;
	h->tfo = true;

	return h;
}

// add a check in the worker
void check_add(hck_handle* hck, struct addrinfo addr, struct sockaddr sockaddr, time_t now, int source, bool tfo = true){
	struct hck_details* h;

	h = keepalive_lookup(hck, addr.ai_addrlen, sockaddr, now, source);

	if (h == NULL) {
		h = create_new_socket(hck, addr.ai_addrlen, sockaddr, now, source, tfo);
	}

	if (h != NULL) {
		assert(hck->sockets.find(h->remote_socket) == hck->sockets.end());
		assert(h->client_socket == source);
		hck->sockets[h->remote_socket] = h;
	}
}

static void http_cleanup(hck_handle& hck, struct hck_details* h){
	if (h->state == hck_details::keepalive){
		//Assert that the DB is in the correct state
		assert(hck.keepalived.find(h->remote_connection) != hck.keepalived.end());

		//Clear the keepalive
		hck.keepalived.erase(h->remote_connection);
	}

	//Close sockets
	close(h->client_socket);
	close(h->remote_socket);

	//Remove from map
	hck.sockets.erase(h->remote_socket);

	//Finally free memory
	delete h;
}

// handle a http event
void handle_http(hck_handle& hck, struct epoll_event e, time_t now){
	int rc;
	struct hck_details* h;
	char respbuff[READSIZE];

	h = hck.sockets[e.data.fd];

	if (h->state == hck_details::connecting){
		if (e.events & EPOLLIN || e.events & EPOLLOUT){
			/* Connection success */
			e.events = EPOLLOUT;
			rc = epoll_ctl(hck.epfd, EPOLL_CTL_MOD, e.data.fd, &e);
			if (rc < 0)
			{
				perror("epoll mod error");
			}
			h->state = hck_details::writing;
		}
		else{
			/* Failed to connect */
			if (h->tfo){
				/* Attempt to re-connect without TFO */
				h->tfo = false;

				hck.sockets.erase(e.data.fd);

				close(h->remote_socket);
				h->remote_socket = create_new_socket(&hck, h->remote_connection_len, h->remote_connection, now, h->client_socket, false);
				hck.sockets[h->remote_socket] = h;

				return;
			}
		}
	}


	/* Do not pass go, do not collect $200 */
	/* An error has occured on the socket, time to cleanup */
	if (e.events & EPOLLERR){
		if (h->state == hck_details::keepalive){
			http_cleanup(hck, h);
		}
		else{
			goto send_failure;
		}
		return;
	}

	if (h->state == hck_details::writing){
		rc = send(e.data.fd, http_request + h->position, http_request_size - h->position, 0);
		if (rc == -1){
			if (errno == EAGAIN || errno == EWOULDBLOCK){
				return;
			}
			fprintf(stdout, "failed to send data (%d)\n", errno);
			if (!h->first){
				goto send_retry;
			}
			goto send_failure;
		}
		h->position += rc;
		if (h->position == http_request_size){
			h->state = hck_details::reading;
			h->position = 0;

			e.events = EPOLLIN;
			rc = epoll_ctl(hck.epfd, EPOLL_CTL_MOD, e.data.fd, &e);
			if (rc < 0)
			{
				perror("epoll mod error");
			}
		}
	}
	else if (h->state == hck_details::reading){
		int i = http_resp_startlen - h->position;
		rc = recv(e.data.fd, respbuff, sizeof(respbuff), 0);
		if (rc  == -1){
			if (errno == EAGAIN || errno == EWOULDBLOCK){
				return;
			}
			fprintf(stdout, "failed to recv data (%d)\n", errno);
			if (!h->first && h->position == 0){
				goto send_retry;
			}
			goto send_failure;
		}

		if (rc > i){
			i -= 1;
			if (respbuff[i] > '0' && respbuff[i] < '5'){
				goto send_ok;
			}
			else{
				fprintf(stdout, "invalid response (char: %d)\n", respbuff[i] - '0');
				goto send_failure;
			}
		}

		h->position += rc;
	}
	else if (h->state == hck_details::keepalive){
		rc = recv(e.data.fd, respbuff, sizeof(respbuff), 0);
		if (rc < 0){
			http_cleanup(hck, h);
			return;
		}
	}
	else if (h->state == hck_details::recovery){
		if (e.events & EPOLLHUP || e.events & EPOLLRDHUP){
			h->expires = 0;
			http_cleanup(hck, h);
			return;
		}

		// Try and make sure we read everything
		rc = recv(e.data.fd, respbuff, sizeof(respbuff), 0);
		if (rc == -1){
			if (errno == EAGAIN || errno == EWOULDBLOCK){
				h->state = hck_details::writing;
				assert(h->position == 0);
			}
			else{
				goto send_retry;
			}
		}
		else if(rc == 0){
			h->state = hck_details::writing;
			assert(h->position == 0);
		}
	}

	if (e.events & EPOLLOUT == 0 && e.events & EPOLLIN == 0 && (e.events & EPOLLHUP || e.events & EPOLLRDHUP)){
		if (h->state == hck_details::keepalive){
			http_cleanup(hck, h);
			return;
		}
		else{
			fprintf(stdout, "connection interrupted\n");
			goto send_failure;
		}
	}

	return;

send_ok:
	if (!send_result(&hck, h->client_socket, 1)){
		perror("failed to send result");
		http_cleanup(hck, h);
		return;
	}
	else{
		h->position = 0;
		h->state = hck_details::keepalive;
		h->expires = now + TIMEOUT_POST;

		/* If a keepalive already exists, don't re-add */
		if (hck.keepalived.find(h->remote_connection) != hck.keepalived.end()) {
			http_cleanup(hck, h);
		}
		else 
		{
			hck.keepalived[h->remote_connection] = h->remote_socket;
		}
	}
	return;
send_failure:
	if (h->state != hck_details::keepalive){
		send_result(&hck, h->client_socket, 0);
	}
	http_cleanup(hck, h);
	return;
send_retry:
	send_result(&hck, h->client_socket, 3);
	http_cleanup(hck, h);
	return;
}

// handle internal communication
void handle_internalsock(hck_handle& hck, int socket, time_t now){
	struct addrinfo servinfo;
	struct sockaddr sa;
	int rc;

	rc = recv(socket, &sa, sizeof(sa), 0);
	if (rc <= 0){
		close(socket);
		return;
	}
	rc = recv(socket, &servinfo, sizeof(addrinfo), 0);
	if (rc <= 0){
		close(socket);
		return;
	}

	check_add(&hck, servinfo, sa, now, socket);
}

void handle_cleanup(hck_handle& hck, time_t now){
	struct hck_details* h;
	std::vector<int> to_delete;

	for (map<int, struct hck_details*>::iterator it = hck.sockets.begin(); it != hck.sockets.end(); it++){
		h = it->second;
		if (h->expires < now){
			to_delete.push_back(it->first);
		}
	}
	for (std::vector<int>::iterator it = to_delete.begin(); it != to_delete.end(); it++){
		int idx = *it;
		h = hck.sockets[*it];
		if (h->state != hck_details::keepalive){
			send_result(&hck, h->client_socket, false);
		}
		hck.sockets.erase(idx);
		close(h->remote_socket);
		delete h;
	}
}

int create_listener(){
	int fd;
	struct sockaddr_un addr;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket error");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	zbx_strlcpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

	unlink(socket_path);

	if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("bind error");
		return -1;
	}

	if (listen(fd, 5) == -1) {
		perror("listen error");
		return -1;
	}

	return fd;
}

/*
Main loop for processing check requests
*/
void main_thread(){
	int n;
	hck_handle hck;
	time_t now;
	time_t lasttime;
	int fd;

	struct epoll_event events[MAXEVENTS];
	struct epoll_event e;
	struct hck_details* h;

	hck.epfd = epoll_create(1024);
	localtime(&now);
	
	/* Create internal listener */
	fd = create_listener();
	if (fd == -1){
		return;
	}

	/* Add the listener to EPOLL */
	e.data.fd = fd;
	e.events = EPOLLIN;
	epoll_ctl(hck.epfd, EPOLL_CTL_ADD, fd, &e);

	while (running){
		/* Update timestamp once per loop */
		time(&now);

		n = epoll_wait(hck.epfd, events, MAXEVENTS, 1000);
		while (n > 0){
			n--;

			e = events[n];

			if (hck.sockets.find(e.data.fd) != hck.sockets.end()){ /* handle events for the checks */
				handle_http(hck, e, now);
			}
			else if (e.data.fd == fd){ 
				/* Handle new connections to the main thread */
				if (e.events & EPOLLIN){
					/* Accept & Add to EPOLL */
					e.data.fd = accept(e.data.fd, 0, 0);
					if (e.data.fd == -1){
						perror("Unable to accept socket for internal communication");
						continue;
					}
					epoll_ctl(hck.epfd, EPOLL_CTL_ADD, e.data.fd, &e);
				}
				else{
					goto cleanup;
					return;
				}
			}
			else{ /* handle events for a connection to the main thread */
				if (e.events & EPOLLIN){
					handle_internalsock(hck, e.data.fd, now);
				}
				else if (e.events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
					//error
					bool found = false;
					for (map<int, struct hck_details*>::iterator it = hck.sockets.begin(); it != hck.sockets.end(); it++){
						struct hck_details* h = it->second;
						if (h->client_socket == e.data.fd){
							assert(!found);//todo: add if debug break
							h->client_socket = -1;
							found = true;
						}
					}

					/* is it not a client socket? */
					if (!found){
						fprintf(stderr, "closing socket %d of unknown type\n", e.data.fd);
					}

					close(e.data.fd);
				}
			}
		}

		if (now > lasttime){
			lasttime = now;
			handle_cleanup(hck, now);
		}
	}

cleanup:
	close(fd);
	for (map<int, struct hck_details*>::iterator it = hck.sockets.begin(); it != hck.sockets.end(); it++){
		close(it->second->client_socket);
		delete it->second;
	}
}

unsigned short execute_check(int fd, const char* addr, const char* port, bool retry = true){
	int rc;
	unsigned short result;
	struct addrinfo hints;
	struct addrinfo *servinfo;  // will point to the results

	memset(&hints, 0, sizeof hints); // make sure the struct is empty
	memset(&servinfo, 0, sizeof servinfo); // make sure the struct is empty

	hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
	hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

	if ((rc = getaddrinfo(addr, port, &hints, &servinfo)) != 0) {
		perror("get addr info failed");
		return 4;
	}

	rc = send(fd, (void*)servinfo->ai_addr, sizeof(*servinfo->ai_addr), 0);
	if (rc < 0){
		freeaddrinfo(servinfo); // free the linked-list
		perror("io error during send (1)");
		return 4;
	}

	rc = send(fd, (void*)servinfo, sizeof(addrinfo), 0);
	if (rc < 0){
		freeaddrinfo(servinfo); // free the linked-list
		perror("io error during send (2)");
		return 4;
	}
	freeaddrinfo(servinfo); // free the linked-list

	rc = recv(fd, &result, sizeof(result), 0);
	if (rc < 0){
		perror("io error during recv");
		return 4;
	}

	if (result == 3){
		if (!retry){
			return 0;
		}

		//retry
		return execute_check(fd, addr, port, false);
	}

	return result;
}

int connect_to_hck(){
	struct sockaddr_un addr;
	int fd;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket error");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	zbx_strlcpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("connect error");
		close(fd);
		return -1;
	}

	return fd;
}

void handle_sighup(int signal){
	running = 0;
}

void processing_thread(){
	// Setup the sighup handler
	struct sigaction sa;
	sa.sa_handler = &handle_sighup;
	sa.sa_flags = SA_RESTART;
	sigfillset(&sa.sa_mask);

	// Intercept SIGHUP
	if (sigaction(SIGHUP, &sa, NULL) == -1) {
		perror("Error: cannot handle SIGHUP"); // Should not happen
	}

	// Send SIGHUP if parent exits
	prctl(PR_SET_PDEATHSIG, SIGHUP);

	// Run until then
	while (running){
		main_thread();
	}

	// As far as we go
	exit(0);
}

extern "C" {
	/******************************************************************************
	*                                                                            *
	* Function: zbx_module_api_version                                           *
	*                                                                            *
	* Purpose: returns version number of the module interface                    *
	*                                                                            *
	* Return value: ZBX_MODULE_API_VERSION_ONE - the only version supported by   *
	*               Zabbix currently                                             *
	*                                                                            *
	******************************************************************************/
	int    zbx_module_api_version()
	{
		return ZBX_MODULE_API_VERSION_ONE;
	}

	/******************************************************************************
	*                                                                            *
	* Function: zbx_module_item_timeout                                          *
	*                                                                            *
	* Purpose: set timeout value for processing of items                         *
	*                                                                            *
	* Parameters: timeout - timeout in seconds, 0 - no timeout set               *
	*                                                                            *
	******************************************************************************/
	void    zbx_module_item_timeout(int timeout)
	{
	}

	/******************************************************************************
	*                                                                            *
	* Function: zbx_module_item_list                                             *
	*                                                                            *
	* Purpose: returns list of item keys supported by the module                 *
	*                                                                            *
	* Return value: list of item keys                                            *
	*                                                                            *
	******************************************************************************/
	ZBX_METRIC    *zbx_module_item_list()
	{
		return keys;
	}

	int hck_fd = -1;

	int    zbx_module_hck_check(AGENT_REQUEST *request, AGENT_RESULT *result)
	{
		unsigned short res;
		char *param1, *param2;

		if (hck_fd == -1){
			hck_fd = connect_to_hck();
		}

		if (hck_fd == -1){
			SET_MSG_RESULT(result, strdup("Unable to connect to worker process"));
			return SYSINFO_RET_FAIL;
		}

		param1 = get_rparam(request, 0);
		param2 = get_rparam(request, 1);

		res = execute_check(hck_fd, param1, param2);

		//an error occured
		if (res > 1){
			close(hck_fd);
			hck_fd = -1;

			res = 0;
		}

		SET_UI64_RESULT(result, res);

		return SYSINFO_RET_OK;
	}

	/******************************************************************************
	*                                                                            *
	* Function: zbx_module_init                                                  *
	*                                                                            *
	* Purpose: the function is called on agent startup                           *
	*          It should be used to call any initialization routines             *
	*                                                                            *
	* Return value: ZBX_MODULE_OK - success                                      *
	*               ZBX_MODULE_FAIL - module initialization failed               *
	*                                                                            *
	* Comment: the module won't be loaded in case of ZBX_MODULE_FAIL             *
	*                                                                            *
	******************************************************************************/
	int    zbx_module_init()
	{
		if (fork() == 0){
			zbx_setproctitle("zabbix_proxy: http check keepalive #1");
			processing_thread();
			exit(1);
		}

		return ZBX_MODULE_OK;
	}

	/******************************************************************************
	*                                                                            *
	* Function: zbx_module_uninit                                                *
	*                                                                            *
	* Purpose: the function is called on agent shutdown                          *
	*          It should be used to cleanup used resources if there are any      *
	*                                                                            *
	* Return value: ZBX_MODULE_OK - success                                      *
	*               ZBX_MODULE_FAIL - function failed                            *
	*                                                                            *
	******************************************************************************/
	int    zbx_module_uninit()
	{
		return ZBX_MODULE_OK;
	}
}