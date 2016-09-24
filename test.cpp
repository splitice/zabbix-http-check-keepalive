#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>

#define CATCH_CONFIG_MAIN
#include "Catch.hpp"
#include "hck_engine.h"

static volatile int shutdown = 1;
extern volatile int running;

const char *socket_path = "\0hct";

void hck_log(int level, const char *fmt, ...){
	va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
	puts("");
	fflush(stdout);
}

static void* thread_function(void*)
{
	running = 1;
	shutdown = 0;
	processing_thread();
	assert(!running);
	shutdown = 1;
}


pthread_t thread1;
static void start_engine(){
	int iret1 = pthread_create(&thread1, NULL, thread_function, NULL);
	sleep(1);
}

static int connect_to_hck_retry()
{
	int fd = connect_to_hck();
	for (int i = 0;fd < 0 && i < 8;i++)
	{
		sleep(1);
		fd = connect_to_hck();
	}
	return fd;
}

static void finish_up()
{
	running = false;
	while (!shutdown) {
		sleep(1);
	}
	pthread_join(thread1, NULL);
}

int fd = 0;

TEST_CASE("Engine tests") {
	if (fd != 0)
	{
		close(fd);
		fd = 0;
		finish_up();
	}
	start_engine();
	fd = connect_to_hck_retry();

	SECTION("Engine start") {
		REQUIRE(fd >= 0);
	}
	
	SECTION("IPv4 Test to Online Host") {
		unsigned short result = execute_check(fd, "216.58.194.174", "80");
	
		REQUIRE(result == 1);
	}

	SECTION("IPv4 Test to Offline Host") {
		unsigned short result = execute_check(fd, "127.123.123.123", "14");
	
		REQUIRE(result == 0);
	}

	SECTION("IPv6 Test to Online Host") {
		unsigned short result = execute_check(fd, "2001:41d0:8:e8ad::1", "80");
	
		REQUIRE(result == 1);
	}
	
	close(fd);
	finish_up();
	fd = 0;
}