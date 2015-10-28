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

#include "openbsd-compat/openbsd-compat.h"
#include "ktest_ssh.h"
#include "ktest_impl.h"

#undef arc4random_buf // openbsd-compat.h

///////////////////////////////////////////////////////////////////////////////
// OpenSSH specific capture
///////////////////////////////////////////////////////////////////////////////

void ktest_ssh_arc4random_buf(void *buf_, size_t n)
{
  unsigned char *buf = (unsigned char*)buf_;
  assert(buf != NULL);

  if (ktest_mode == KTEST_NONE) {
    arc4random_buf(buf, n);
    return;
  }
  else if (ktest_mode == KTEST_RECORD) {
    arc4random_buf(buf, n);
    if (KTEST_DEBUG) {
      fprintf(stderr, "KTEST: arc4random_buf generated %zd bytes: ", n);
      fprintf_bytes(stderr, buf, n);
    }
    KTOV_append(&ktov, ktest_object_names[RNG], n, buf);
    return;
  }
  else if (ktest_mode == KTEST_PLAYBACK) {
    KTestObject *o = KTOV_next_object(&ktov, ktest_object_names[RNG]);
    if (o->numBytes != n) {
      fprintf(stderr,
	      "KTEST: arc4random_buf playback error: %zd bytes requested, "
	      "%d bytes recorded", n, o->numBytes);
      exit(2);
    }
    memcpy(buf, o->bytes, n);
    if (KTEST_DEBUG) {
      fprintf(stderr, "KTEST: arc4random_buf playback [%zd] ", n);
      fprintf_bytes(stdout, buf, o->numBytes);
    }
    return;
  }
}
