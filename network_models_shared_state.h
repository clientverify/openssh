#include <stddef.h>

ServerOptions* get_server_options();
void  set_server_version_string(char* s);
char* get_server_version_string(void);
Buffer* get_incoming_packet();
Buffer* get_input();
