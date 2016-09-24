void processing_thread();
int connect_to_hck();
unsigned short execute_check(int fd, const char* addr, const char* port, bool retry = true);