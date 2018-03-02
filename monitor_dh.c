#include "monitor_dh.h"
#include "KTest_openssh.h"
#include <assert.h>

#define MAX_LEN 1000
DH* ktest_verify_choose_dh(int min, int wantbits, int max){
  printf("ktest_verify_choose_dh entered\n");
  if(arg_ktest_mode == KTEST_NONE){
    return ktest_verify_choose_dh(min, wantbits, max);
  } else if (arg_ktest_mode == KTEST_RECORD){
    printf("ktest_verify_choose_dh calling writesocket with min %d, wantbits %d, max %d\n", min, wantbits, max);
    ktest_writesocket(verification_socket, (char*)&min, sizeof(min));
    ktest_writesocket(verification_socket, (char*)&wantbits, sizeof(wantbits));
    ktest_writesocket(verification_socket, (char*)&max, sizeof(max));
    DH* ret = choose_dh(min, wantbits, max);

    //modulus (p):
    unsigned char *to = malloc(BN_num_bytes(ret->p)); 
    int len = BN_bn2bin(ret->p, to);
    assert(len < MAX_LEN);
    ktest_record_readbuf(verification_socket, (char*)to, len);
    free(to);

    //gen (g):
    to = malloc(BN_num_bytes(ret->g)); 
    len = BN_bn2bin(ret->g, to);
    assert(len < MAX_LEN);
    ktest_record_readbuf(verification_socket, (char*)to, len);
    free(to);

    return ret;
  } else if (arg_ktest_mode == KTEST_PLAYBACK){
    printf("ktest_verify_choose_dh calling writesocket with min %d, wantbits %d, max %d\n", min, wantbits, max);
    ktest_writesocket(verification_socket, (char*)&min, sizeof(min));
    ktest_writesocket(verification_socket, (char*)&wantbits, sizeof(wantbits));
    ktest_writesocket(verification_socket, (char*)&max, sizeof(max));

    //dealing with the fact that the call this models has a single call to
    //arc4random().
    arc4random();

    unsigned char *from = malloc(MAX_LEN);

    //recover p
    int len = ktest_readsocket(verification_socket, (char*)from, MAX_LEN);
    BIGNUM *p = BN_bin2bn(from, len, NULL);

    //recover g
    len = ktest_readsocket(verification_socket, (char*)from, MAX_LEN);
    BIGNUM *g = BN_bin2bn(from, len, NULL);

    free(from);

    return dh_new_group(g, p);
  } else assert(0);

}
