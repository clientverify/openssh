//===-- ktest_ssh.h ---------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
// This file contains OpenSSH-specific KTest code for recording and playing
// back an SSH session.
//
//===----------------------------------------------------------------------===//

#ifndef __KTEST_SSH_H__
#define __KTEST_SSH_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include "ktest.h"

#ifdef __cplusplus
extern "C" {
#endif

  /*
  // Network capture for Cliver
  int ktest_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  int ktest_select(int nfds, fd_set *readfds, fd_set *writefds,
		  fd_set *exceptfds, struct timeval *timeout);
  ssize_t ktest_writesocket(int fd, const void *buf, size_t count);
  ssize_t ktest_readsocket(int fd, void *buf, size_t count);

  // stdin capture for Cliver
  int ktest_raw_read_stdin(void *buf, int siz);

  // Random number generator capture for Cliver
  int ktest_RAND_bytes(unsigned char *buf, int num);
  int ktest_RAND_pseudo_bytes(unsigned char *buf, int num);

  // Time capture for Cliver (actually unnecessary!)
  time_t ktest_time(time_t *t);

  // TLS Master Secret capture for Cliver
  void ktest_master_secret(unsigned char *ms, int len);
  */

#ifdef __cplusplus
}
#endif

#endif // __KTEST_SSH_H__
