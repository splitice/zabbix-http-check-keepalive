#include <stdio.h>
#include <stdarg.h>
#define CATCH_CONFIG_MAIN
#include "Catch.hpp"
#include "hck_engine.h"

static bool shutdown = true;
extern bool running;

void hck_log(int level, const char *fmt, ...){
	va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
	puts("");
}

static void start_engine(){
	if (fork() == 0){
		zbx_setproctitle("zabbix_proxy: http check keepalive #1");
		shutdown = false;
		processing_thread();
		shutdown = true;
		exit(1);
	}
}

TEST_CASE( "IPv4 Test to Online Host" ) {
    start_engine();
	int fd = connect_to_hck();
	
	unsigned short result = execute_check(fd, "216.58.194.174","80");
	
	REQUIRE( result == 1 );
	
	close(fd);
	
	running = false;
	while(!shutdown){
		sleep(1);
	}
}

TEST_CASE( "IPv4 Test to Offline Host" ) {
    start_engine();
	int fd = connect_to_hck();
	
	unsigned short result = execute_check(fd, "127.123.123.123","14");
	
	REQUIRE( result == 0 );
	
	close(fd);
	
	running = false;
	while(!shutdown){
		sleep(1);
	}
}