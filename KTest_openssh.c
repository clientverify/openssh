#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pty.h>
#include <assert.h>
#include <unistd.h>

#include "KTest_openssh.h"
#include "openbsd-compat/bsd-arc4random.h"
unsigned int ktest_arc4random()
{
  if (ktest_get_mode() == KTEST_NONE) {
    return arc4random();
  } else if (ktest_get_mode() == KTEST_RECORD) {
    unsigned int ret = arc4random();
    if (KTEST_DEBUG) printf("ktest_arc4random recording %u\n", ret);
    KTOV_append(&ktov, ktest_object_names[ARC4RNG], sizeof(ret), &ret);
    return ret;
  } else if (ktest_get_mode() == KTEST_PLAYBACK) {
    KTestObject *o = KTOV_next_object(&ktov, ktest_object_names[ARC4RNG]);
    assert(o->numBytes == sizeof(unsigned int));
    unsigned int ret = *((unsigned int*) o->bytes);

    if (KTEST_DEBUG){
      printf("arc4random playback %u\n", ret);
      unsigned int tmp = arc4random();
      if (tmp != ret) printf("arc4random playback ret should be: %u is: %u\n", tmp, ret);
      assert(tmp == ret);
    }
    return ret;
  } else {
    perror("ktest_RAND_bytes coding error - should never get here");
    exit(4);
  }
}


int ktest_pipe(int pipefd[2]){
  int ret = pipe(pipefd);
  assert(ret == 0); //assume success
  if((ktest_get_mode() == KTEST_RECORD) || (ktest_get_mode() == KTEST_PLAYBACK)) {
    insert_ktest_sockfd(pipefd[0]);
    insert_ktest_sockfd(pipefd[1]);
  }
  return ret;
}

int ktest_open(const char *path, int oflag){
  int fd = open(path, oflag);
  assert(fd >= 0);
  if((ktest_get_mode() == KTEST_RECORD) || (ktest_get_mode() == KTEST_PLAYBACK)) {
    insert_ktest_sockfd(fd);
  }
  return fd;
}

int ktest_openpty(int *ptyfd, int *ttyfd, char *name, const struct termios *termp, const struct winsize *winp)
{
  assert(name  == 0);
  assert(termp == 0);
  assert(winp  == 0);
  if (ktest_get_mode() == KTEST_NONE){
    return openpty(ptyfd, ttyfd, name, termp, winp);
  }else if(ktest_get_mode() == KTEST_RECORD) { // passthrough
    int ret = openpty(ptyfd, ttyfd, name, termp, winp);
    insert_ktest_sockfd(*ptyfd); // record the socket descriptor of interest
    insert_ktest_sockfd(*ttyfd); // record the socket descriptor of interest

    return ret;
  } else if (ktest_get_mode() == KTEST_PLAYBACK) {
    int ret = openpty(ptyfd, ttyfd, name, termp, winp);
    assert(*ptyfd >= 0);
    assert(*ttyfd >= 0);
    insert_ktest_sockfd(*ptyfd); // record the socket descriptor of interest
    insert_ktest_sockfd(*ttyfd); // record the socket descriptor of interest

    return ret;
  } else {
    perror("ktest_openpty error - should never get here");
    exit(4);
  }
}

