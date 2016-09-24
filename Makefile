zabbix_http_check_keepalive: zabbix_http_check_keepalive.cpp hck_engine.cpp
	g++ -fPIC -shared -o zabbix_http_check_keepalive.so zabbix_http_check_keepalive.cpp hck_engine.cpp -I../../../include

tests: test.cpp hck_engine.cpp
	g++ -fPIC -shared -o zabbix_http_check_keepalive.so test.cpp hck_engine.cpp -I../../../include