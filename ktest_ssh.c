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
#include <ctype.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include <sys/time.h>

//#include <openssl/rand.h>
//#undef RAND_bytes
//#undef RAND_pseudo_bytes

#include "ktest_ssh.h"

///////////////////////////////////////////////////////////////////////////////
// OpenSSH specific capture
///////////////////////////////////////////////////////////////////////////////

