#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pty.h>
#include <assert.h>
#include <unistd.h>

#include "KTest_openssh.h"

int ktest_pipe(int pipefd[2]){
  int ret = pipe(pipefd);
  assert(ret == 0); //assume success
  if((ktest_get_mode() == KTEST_RECORD) || (ktest_get_mode() == KTEST_PLAYBACK)) {
    insert_ktest_sockfd(pipefd[0]);
    insert_ktest_sockfd(pipefd[1]);
  }
  return ret;
}

int ktest_socketpair(int domain, int type, int protocol, int sv[2]){
  int ret = socketpair(domain, type, protocol, sv);
  assert(ret == 0); //assume success
  if((ktest_get_mode() == KTEST_RECORD) || (ktest_get_mode() == KTEST_PLAYBACK)) {
    insert_ktest_sockfd(sv[0]);
    insert_ktest_sockfd(sv[1]);
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
  //We're assuming that arg_ktest_mode is consistent with KTest.c's ktest_mode.
  enum kTestMode ktest_mode = ktest_get_mode();
  assert(name  == 0);
  assert(termp == 0);
  assert(winp  == 0);
  if (ktest_mode == KTEST_NONE){
    return openpty(ptyfd, ttyfd, name, termp, winp);
  }else if(ktest_mode == KTEST_RECORD) { // passthrough
    int ret = openpty(ptyfd, ttyfd, name, termp, winp);
    insert_ktest_sockfd(*ptyfd); // record the socket descriptor of interest
    insert_ktest_sockfd(*ttyfd); // record the socket descriptor of interest

    return ret;
  } else if (ktest_mode == KTEST_PLAYBACK) {
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

