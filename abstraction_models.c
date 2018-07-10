//#include "monitor_dh.h"
#include "KTest_openssh.h"
#include "buffer.h"
#include "log.h"
#include "servconf.h"
#include "network_models_shared_state.h"
#include "ssh1.h"
#include "ssh2.h"
#include "packet.h"
#include "kex.h"

#include <assert.h>

#define MAX_SZ 512
int
ktest_packet_read_poll2(u_int32_t *seqnr_p)
{
  if(ktest_get_mode() == KTEST_NONE){
    int type = packet_read_poll2(seqnr_p);
    return type;
  } else if (ktest_get_mode() == KTEST_RECORD){
    Buffer *incoming_packet = get_incoming_packet();
    Buffer *input = get_input();
    int start_input_offset = input->offset;
    int type = -1;

    ktest_set_mode_off();
    type = packet_read_poll2(seqnr_p);
    ktest_set_mode_on();

    //record type
    ktest_record_readbuf(monitor_socket, (char*)&type, sizeof(type));
    if(type == SSH_MSG_NONE){
      return type;
    }

    //record amount consumed from input
    int end_input_offset = input->offset;
    assert(end_input_offset >= start_input_offset);
    int eaten = end_input_offset - start_input_offset;
    ktest_record_readbuf(monitor_socket, (char*)&eaten, sizeof(eaten));

    //record the incoming packet's buffer
    assert(incoming_packet->end - incoming_packet->offset < MAX_SZ);
    ktest_record_readbuf(monitor_socket,
        incoming_packet->buf + incoming_packet->offset,
        incoming_packet->end - incoming_packet->offset);
    return type;
  } else if (ktest_get_mode() == KTEST_PLAYBACK){
    Buffer *incoming_packet = get_incoming_packet();
    Buffer *input = get_input();
    int type = -1;

    int len = ktest_readsocket(monitor_socket, (char*)&type, sizeof(type));
    if(type == SSH_MSG_NONE) return type;
    if(type == SSH2_MSG_NEWKEYS){
      set_newkeys(MODE_IN);
    }

    int eaten = -1;
    len = ktest_readsocket(monitor_socket, (char*)&eaten, sizeof(eaten));
    buffer_consume(input, eaten);

    char* buf = malloc(MAX_SZ);
    int need = ktest_readsocket(monitor_socket, buf, MAX_SZ);
    buffer_clear(incoming_packet);
    buffer_append(incoming_packet, buf, need);
    free(buf);
    return type;
  }
}
