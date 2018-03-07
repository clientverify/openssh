#include "monitor_dh.h"
#include "KTest_openssh.h"
#include <assert.h>
#include <openssl/rsa.h>

#define MAX_LEN 1000
int bn_to_buf(unsigned char **buf_ptr, BIGNUM* bn){
    int size = BN_num_bytes(bn); //should size and len always be the same?
    unsigned char *to = malloc(size); 
    int len = BN_bn2bin(bn, to);
    assert(len < MAX_LEN);
    *buf_ptr = to;
    return len;
}

DH* ktest_verify_choose_dh(int min, int wantbits, int max){
  printf("ktest_verify_choose_dh entered\n");
  if(ktest_get_mode() == KTEST_NONE){
    return choose_dh(min, wantbits, max);
  } else if (ktest_get_mode() == KTEST_RECORD){
    printf("ktest_verify_choose_dh calling writesocket with min %d, wantbits %d, max %d\n", min, wantbits, max);
    ktest_writesocket(verification_socket, (char*)&min, sizeof(min));
    ktest_writesocket(verification_socket, (char*)&wantbits, sizeof(wantbits));
    ktest_writesocket(verification_socket, (char*)&max, sizeof(max));


    ktest_set_mode_off();
    DH* ret = choose_dh(min, wantbits, max);
    ktest_set_mode_on();

    //modulus (p):
    unsigned char *to;
    int len = bn_to_buf(&to, ret->p);
    ktest_record_readbuf(verification_socket, (char*)to, len);
    free(to);

    //gen (g):
    len = bn_to_buf(&to, ret->g);
    ktest_record_readbuf(verification_socket, (char*)to, len);
    free(to);

    return ret;
  } else if (ktest_get_mode() == KTEST_PLAYBACK){
    printf("ktest_verify_choose_dh calling writesocket with min %d, wantbits %d, max %d\n", min, wantbits, max);
    ktest_writesocket(verification_socket, (char*)&min, sizeof(min));
    ktest_writesocket(verification_socket, (char*)&wantbits, sizeof(wantbits));
    ktest_writesocket(verification_socket, (char*)&max, sizeof(max));

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


int ktest_verify_DH_generate_key(DH *dh){
  printf("ktest_verify_DH_generate_key entered\n");
  if(ktest_get_mode() == KTEST_NONE){
    return DH_generate_key(dh);
  } else if (ktest_get_mode() == KTEST_RECORD){
    unsigned char *to;
    int len = bn_to_buf(&to, dh->p);
    ktest_writesocket(verification_socket, to, len);
    free(to);

    len = bn_to_buf(&to, dh->g);
    ktest_writesocket(verification_socket, to, len);
    free(to);

    //may be null...
    int priv_was_null = -1;
    if(dh->priv_key != NULL){
      priv_was_null = 0;
      len = bn_to_buf(&to, dh->priv_key);
      ktest_writesocket(verification_socket, to, len);
      free(to);
    } else {
      priv_was_null = 1;
      ktest_writesocket(verification_socket, NULL, 0);
    }

    ktest_set_mode_off();
    DH* dh_2 = DH_new();
    dh_2->p        = dh->p;
    dh_2->g        = dh->g;
    dh_2->priv_key = dh->priv_key;
    int ret = DH_generate_key(dh_2);
    ktest_set_mode_on();

    if(!priv_was_null){
      dh->priv_key = dh_2->priv_key;
      len = bn_to_buf(&to, dh->priv_key);
      ktest_record_readbuf(verification_socket, to, len);
      free(to);
    }

    dh->pub_key  = dh_2->pub_key;
    len = bn_to_buf(&to, dh->pub_key);
    ktest_record_readbuf(verification_socket, to, len);
    free(to);


    //must not free the following:
    dh_2->p        = NULL;
    dh_2->g        = NULL;
    dh_2->priv_key = NULL;
    dh_2->pub_key  = NULL;
    DH_free(dh_2);

    ktest_record_readbuf(verification_socket, &ret, sizeof(ret));
    return ret;
  } else if (ktest_get_mode() == KTEST_PLAYBACK){
    //writing inputs
    unsigned char *to;
    int len = bn_to_buf(&to, dh->p);
    ktest_writesocket(verification_socket, to, len);
    free(to);

    len = bn_to_buf(&to, dh->g);
    ktest_writesocket(verification_socket, to, len);
    free(to);

    //If dh->priv_key is null, we don't need to send it, but we do need to read
    //it.
    int priv_was_null = -1;
    if(dh->priv_key != NULL){
      priv_was_null = 0;
      len = bn_to_buf(&to, dh->priv_key);
      ktest_writesocket(verification_socket, to, len);
      free(to);
    } else {
      priv_was_null = 1;
      ktest_writesocket(verification_socket, NULL, 0);
    }

    //Reading results
    unsigned char *from = malloc(MAX_LEN);
    if(!priv_was_null){//Reading dh->priv_key if was null
      len = ktest_readsocket(verification_socket, (char*)from, MAX_LEN);
      dh->priv_key = BN_bin2bn(from, len, NULL);
    }

    //Reading dh->pub_key
    len = ktest_readsocket(verification_socket, (char*)from, MAX_LEN);
    dh->pub_key = BN_bin2bn(from, len, NULL);
    free(from);

    int ret = -1;
    ktest_readsocket(verification_socket, &ret, sizeof(ret));

    return ret;

  } else assert(0);
}


int ktest_verify_RSA_sign(int type, const unsigned char *m, unsigned int m_len,
        unsigned char *sigret, unsigned int *siglen, RSA *rsa){
  printf("ktest_verify_RSA_sign entered\n");
  if(ktest_get_mode() == KTEST_NONE){
    return RSA_sign(type, m, m_len, sigret, siglen, rsa);
  } else if (ktest_get_mode() == KTEST_RECORD){
    //Send:  type, m (m_len)
    ktest_writesocket(verification_socket, &type, sizeof(type));
    ktest_writesocket(verification_socket, m, m_len);

    //Send important parts of rsa: n, d, p, q
    unsigned char *to;
    int len = bn_to_buf(&to, rsa->n);
    ktest_writesocket(verification_socket, to, len);
    free(to);

    len = bn_to_buf(&to, rsa->d);
    ktest_writesocket(verification_socket, to, len);
    free(to);

    len = bn_to_buf(&to, rsa->p);
    ktest_writesocket(verification_socket, to, len);
    free(to);

    len = bn_to_buf(&to, rsa->q);
    ktest_writesocket(verification_socket, to, len);
    free(to);


    ktest_set_mode_off();
    RSA* rsa_2 = RSA_new();
    rsa_2->n = rsa->n;
    rsa_2->d = rsa->d;
    rsa_2->p = rsa->p;
    rsa_2->q = rsa->q;
    int ret = RSA_sign(type, m, m_len, sigret, siglen, rsa_2);

    //must not free the following:
    rsa_2->n = NULL;
    rsa_2->d = NULL;
    rsa_2->p = NULL;
    rsa_2->q = NULL;
    RSA_free(rsa_2);
    ktest_set_mode_on();

    //Return values: sig, siglen, ret
    ktest_record_readbuf(verification_socket, sigret, *siglen);

    ktest_record_readbuf(verification_socket, &ret, sizeof(ret));
    return ret;
  } else if (ktest_get_mode() == KTEST_PLAYBACK){
    //Send:  type, m (m_len)
    ktest_writesocket(verification_socket, &type, sizeof(type));
    ktest_writesocket(verification_socket, m, m_len);

    //Send important parts of rsa: n, d, p, q
    unsigned char *to;
    int len = bn_to_buf(&to, rsa->n);
    ktest_writesocket(verification_socket, to, len);
    free(to);

    len = bn_to_buf(&to, rsa->d);
    ktest_writesocket(verification_socket, to, len);
    free(to);

    len = bn_to_buf(&to, rsa->p);
    ktest_writesocket(verification_socket, to, len);
    free(to);

    len = bn_to_buf(&to, rsa->q);
    ktest_writesocket(verification_socket, to, len);
    free(to);

    //Return values: sig, siglen, ret
    *siglen = ktest_readsocket(verification_socket, sigret, RSA_size(rsa));
    int ret = -1;
    ktest_readsocket(verification_socket, &ret, sizeof(ret));
    return ret;

  } else assert(0);
}
