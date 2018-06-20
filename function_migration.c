#include "KTest_openssh.h"
#include <assert.h>

void ktest_verify_send_string(char* str){
  if(ktest_get_mode() == KTEST_NONE){
  } else if (ktest_get_mode() == KTEST_RECORD){
    do_not_record_this_record();
    //to model the call out to the monitor we must have a
    //writesocket:
    ktest_writesocket(monitor_socket, str, strlen(str));
  } else if (ktest_get_mode() == KTEST_PLAYBACK){
    ktest_writesocket(monitor_socket, str, strlen(str));
  } else assert(0);
}
