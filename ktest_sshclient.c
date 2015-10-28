//===-- ktest_ssh.c -------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
// OpenSSH-specific KTest code for recording and playing back an SSH session.
//
//===----------------------------------------------------------------------===//

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "ktest_ssh.h"
#include "ktest_impl.h"

///////////////////////////////////////////////////////////////////////////////
// OpenSSH client (ssh command) capture
///////////////////////////////////////////////////////////////////////////////

// declare original function (from sshconnect.c)
int timeout_connect(int sockfd, const struct sockaddr *serv_addr,
    socklen_t addrlen, int *timeoutp);

int ktest_ssh_timeout_connect(int sockfd, const struct sockaddr *serv_addr,
    socklen_t addrlen, int *timeoutp)
{
  if (ktest_mode == KTEST_NONE) { // passthrough
      return timeout_connect(sockfd, serv_addr, addrlen, timeoutp);
  }
  else if (ktest_mode == KTEST_RECORD) {
      int ret;
      ktest_sockfd = sockfd; // record the socket descriptor of interest
      ret = timeout_connect(sockfd, serv_addr, addrlen, timeoutp);
      if (KTEST_DEBUG) {
        fprintf(stderr,
            "KTEST: timeout_connect() called on socket (%d)\n", sockfd);
      }
      return ret;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
      ktest_sockfd = sockfd; // record the socket descriptor of interest
      if (KTEST_DEBUG) {
        fprintf(stderr,
            "KTEST: timeout_connect() called on socket (%d)\n", sockfd);
      }
      return 0; // assume success
  }
  else {
    perror("ktest_ssh_timeout_connect error - should never get here");
    exit(4);
  }
}
