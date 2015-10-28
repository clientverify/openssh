//===-- ktest.h --------------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
// Generic KTest functions for recording/playing back sessions.
//
// IMPORTANT NOTE: #include this header file AFTER any system includes, so that
// it can override any definitions (such as FD_ZERO) necessary.
//
//===----------------------------------------------------------------------===//

#ifndef __KTEST_H__
#define __KTEST_H__

#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KTEST_DEBUG 0
#define KTEST_VERSION 4 // Cliver-specific (incompatible with normal klee)
#define KTEST_MAGIC_SIZE 5
#define KTEST_MAGIC "KTEST"
#define BOUT_MAGIC "BOUT\n" // for compatibility

// override inline assembly version of FD_ZERO from
// /usr/include/x86_64-linux-gnu/bits/select.h
#ifdef FD_ZERO
#undef FD_ZERO
#endif
#define FD_ZERO(p)        memset((char *)(p), 0, sizeof(*(p)))

///////////////// KTest struct definitions ///////////////////

typedef struct KTestObject KTestObject;
struct KTestObject {
  char *name;
  struct timeval timestamp;
  unsigned numBytes;
  unsigned char *bytes;
};

typedef struct KTest KTest;
struct KTest {
  /* file format version */
  unsigned version;

  unsigned numArgs;
  char **args;

  unsigned symArgvs;
  unsigned symArgvLen;

  unsigned numObjects;
  KTestObject *objects;
};

//////////////// Exported functions ///////////////////

/* returns the current .ktest file format version */
unsigned kTest_getCurrentVersion();

/* return true iff file at path matches KTest header */
int kTest_isKTestFile(const char *path);

/* returns NULL on (unspecified) error */
KTest* kTest_fromFile(const char *path);

/* returns 1 on success, 0 on (unspecified) error */
int kTest_toFile(KTest *, const char *path);

/* returns total number of object bytes */
unsigned kTest_numBytes(KTest *);

void kTest_free(KTest *);

// Capture mode
enum kTestMode {KTEST_NONE, KTEST_RECORD, KTEST_PLAYBACK};

// Start/finish logfile
void ktest_start(const char *filename, enum kTestMode mode);
void ktest_finish(); // write capture to file


#ifdef __cplusplus
}
#endif

#endif // __KTEST_H___
