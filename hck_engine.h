void processing_thread();
int connect_to_hck();
double execute_check(int fd, const char* addr, const char* port, bool retry = true);