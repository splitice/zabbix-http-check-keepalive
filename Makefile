zabbix_http_check_keepalive: zabbix_http_check_keepalive.cpp
	g++ -fPIC -shared -o zabbix_http_check_keepalive.so zabbix_http_check_keepalive.cpp -I../../../include
