//===-- ktest_impl.h ---------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
// Generic KTest functions for recording/playing back sessions -
// implementation.
//
// IMPORTANT NOTE: #include this header file AFTER any system includes, so that
// it can override any definitions (such as FD_ZERO) necessary.
//
//===----------------------------------------------------------------------===//

#ifndef __KTEST_IMPL_H__
#define __KTEST_IMPL_H__

#include <sys/select.h>
#include "ktest.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct KTestObjectVector {
  KTestObject *objects;
  int size;
  int capacity; // capacity >= size
  int playback_index; // starts at 0
} KTestObjectVector;

enum { CLIENT_TO_SERVER=0, SERVER_TO_CLIENT, RNG, PRNG, TIME, STDIN, SELECT,
  MASTER_SECRET };
static char* ktest_object_names[] = {
  "c2s", "s2c", "rng", "prng", "time", "stdin", "select", "master_secret"
};

extern KTestObjectVector ktov;  // contains network, time, and prng captures
extern enum kTestMode ktest_mode;
extern const char *ktest_output_file;
extern const char *ktest_network_file;
extern int ktest_sockfd; // descriptor of the socket we're capturing

void KTOV_append(KTestObjectVector *ov, const char *name, int num_bytes,
    const void *bytes);
KTestObject* KTOV_next_object(KTestObjectVector *ov, const char *name);
void print_fd_set(int nfds, fd_set *fds);

#ifdef __cplusplus
}
#endif

#endif // __KTEST_IMPL_H__
