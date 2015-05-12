#include <sys/epoll.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h> //inet_addr
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
int http_resp_startlen = sizeof("HTTP/1.0 ");//or "HTTP 1.1" same length

#define READSIZE 1024
#define MAXEVENTS 16

char *socket_path = "\0hck";
volatile int running = 1;

using namespace std;


// a check
struct hck_details {
	time_t expires;
	int socket;
	int client_sock;
	unsigned short position: 16;
	enum {
		connecting,
		writing,
		reading,
		keepalive,
		recovery
	} state: 16;
};

// the hck system (could be exported outside of zabbix in future)
class hck_handle {
public:
	int epfd;
	map<int, struct hck_details*> sockets;
};

//send result from worker -> process
void send_result(hck_handle* hck, int sock, unsigned short result){
	send(sock, &result, sizeof(result), 0);
}

// add a check in the worker
void check_add(hck_handle* hck, in_addr_t host, unsigned short port, time_t now, int source){
	int socket_desc;
	struct sockaddr_in server;
	struct epoll_event e;
	int rc;
	struct hck_details* h;


	for (map<int, struct hck_details*>::iterator it = hck->sockets.begin(); it != hck->sockets.end(); it++){
		h = it->second;

		if (h->state == hck_details::keepalive){
			h->state = hck_details::recovery;
			h->position = 0;
			h->expires = now + 2;
			h->client_sock = source;
			return;
		}
	}

	h = new struct hck_details;

	//Create socket
	socket_desc = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (socket_desc == -1)
	{
		return;
	}

	server.sin_addr.s_addr = host;
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	//Connect to remote server
	rc = connect(socket_desc, (struct sockaddr *)&server, sizeof(server));
	if (rc < 0)
	{
		if (errno != EAGAIN && errno != EINPROGRESS){
			perror("error connecting");
			delete h;
			return;
		}


		e.events = EPOLLIN | EPOLLOUT;
		h->state = hck_details::connecting;
	}
	else{
		e.events = EPOLLOUT;
		h->state = hck_details::writing;
	}
	e.data.fd = socket_desc;
	rc = epoll_ctl(hck->epfd, EPOLL_CTL_ADD, socket_desc, &e);
	if (rc < 0)
	{
		perror("epoll add error");
		delete h;
		return;
	}

	h->expires = now + 3;
	h->client_sock = source;
	h->position = 0;
	h->socket = socket_desc;

	hck->sockets[socket_desc] = h;
}

// handle a http event
void handle_http(hck_handle& hck, struct epoll_event e, time_t now){
	int rc;
	struct hck_details* h;
	char respbuff[READSIZE];

	h = hck.sockets[e.data.fd];

	if (e.events & EPOLLHUP){
		goto send_failure;
	}

	if (h->state == hck_details::connecting){
		e.events = EPOLLOUT;
		rc = epoll_ctl(hck.epfd, EPOLL_CTL_MOD, e.data.fd, &e);
		if (rc < 0)
		{
			perror("epoll mod error");
		}
		h->state = hck_details::writing;
	}
	if (h->state == hck_details::writing){
		rc = send(e.data.fd, http_request + h->position, sizeof(http_request) - h->position, 0);
		if (rc < 0){
			goto send_failure;
		}
		h->position += rc;
		if (h->position == sizeof(http_request)){
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
		rc = recv(e.data.fd, respbuff, sizeof(respbuff), 0);
		if (rc <= 0){
			goto send_failure;
		}

		int i = http_resp_startlen - 1 - h->position;
		if (rc >= i){
			if (respbuff[i] > '0' && respbuff[i] < '5'){
				goto send_ok;
			}
			else{
				goto send_failure;
			}
		}

		h->position += rc;
	}
	else if (h->state == hck_details::keepalive){
		rc = recv(e.data.fd, respbuff, sizeof(respbuff), 0);
		if (rc <= 0){
			goto send_failure;
		}
	}
	else if (h->state == hck_details::recovery){
		if (e.events & EPOLLIN || e.events & EPOLLHUP){
			rc = recv(e.data.fd, respbuff, sizeof(respbuff), 0);
			if (rc <= 0){
				h->expires = 0;
				goto send_retry;
			}
		}
		if (e.events & EPOLLOUT){
			h->state = hck_details::writing;
		}
	}
	return;

clear:
	hck.sockets.erase(h->socket);
	close(h->socket);
	delete h;
	return;
send_ok:
	send_result(&hck, h->client_sock, 1);
	h->position = 0;
	h->state = hck_details::keepalive;
	h->expires = now + 60;
	return;
send_failure:
	if (h->state != hck_details::keepalive){
		send_result(&hck, h->client_sock, 0);
	}
	goto clear;
send_retry:
	send_result(&hck, h->client_sock, 3);
	goto clear;
}

// handle internal communication
void handle_internalsock(hck_handle& hck, int socket, time_t now){
	in_addr_t inaddr;
	unsigned short port;

	recv(socket, &inaddr, sizeof(inaddr), 0);
	recv(socket, &port, sizeof(port), 0);

	check_add(&hck, inaddr, port, now, socket);
}

void handle_cleanup(hck_handle& hck, time_t now){
	struct hck_details* h;
	std::vector<int> to_delete;

	for (map<int, struct hck_details*>::iterator it = hck.sockets.begin(); it != hck.sockets.end(); it++){
		struct hck_details* h = it->second;
		if (h->expires < now){
			to_delete.push_back(it->first);
		}
	}
	for (std::vector<int>::iterator it = to_delete.begin(); it != to_delete.end(); it++){
		h = hck.sockets[*it];
		if (h->state != hck_details::keepalive){
			send_result(&hck, h->client_sock, false);
		}
		hck.sockets.erase(h->socket);
		close(h->socket);
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
	
	fd = create_listener();
	if (fd == -1){
		return;
	}

	e.data.fd = fd;
	e.events = EPOLLIN;
	epoll_ctl(hck.epfd, EPOLL_CTL_ADD, fd, &e);

	while (running){
		time(&now);
		n = epoll_wait(hck.epfd, events, MAXEVENTS, 1000);
		while (n > 0){
			n--;

			e = events[n];

			if (hck.sockets.find(e.data.fd) != hck.sockets.end()){
				handle_http(hck, e, now);
			}
			else if (e.data.fd == fd){
				if (e.events & EPOLLIN){
					e.data.fd = accept(e.data.fd, 0, 0);
					epoll_ctl(hck.epfd, EPOLL_CTL_ADD, e.data.fd, &e);
				}
				else{
					goto cleanup;
				}
			}
			else{
				if (e.events & EPOLLIN){
					handle_internalsock(hck, e.data.fd, now);
				}
				else{
					//error
					goto cleanup;
				}
			}
		}

		if (now != lasttime){
			lasttime = now;
			handle_cleanup(hck, now);
		}
	}

cleanup:
	close(fd);
	for (map<int, struct hck_details*>::iterator it = hck.sockets.begin(); it != hck.sockets.end(); it++){
		delete it->second;
	}
}

unsigned short execute_check(int fd, const char* addr, unsigned short port, bool retry = true){
	int rc;
	in_addr_t inaddr = inet_addr(addr);

	rc = write(fd, &inaddr, sizeof(inaddr));
	if (rc < 0){
		goto error;
	}
	rc = write(fd, &port, sizeof(port));
	if (rc < 0){
		goto error;
	}

	unsigned short result;

	rc = read(fd, &result, sizeof(result));
	if (rc < 0){
		goto error;
	}

	if (result == 3){
		if (!retry){
			return 0;
		}

		//retry
		return execute_check(fd, addr, port, false);
	}

	return result;

error:
	perror("io error");
	return 4;
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
		int port;

		if (hck_fd == -1){
			hck_fd = connect_to_hck();
		}

		if (hck_fd == -1){
			SET_MSG_RESULT(result, strdup("Unable to connect to worker process"));
			return SYSINFO_RET_FAIL;
		}

		param1 = get_rparam(request, 0);
		param2 = get_rparam(request, 1);
		port = atoi(param2);

		res = execute_check(hck_fd, param1, port);

		if (res > 1){
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