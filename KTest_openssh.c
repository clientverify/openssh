#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pty.h>
#include <assert.h>
#include <unistd.h>

#include "KTest_openssh.h"
#if 0
//Return the same fake pid everytime for debugging.
#define KTEST_FORK_DUMMY_CHILD_PID 37

//which is the parent or child--whichever we wish to continue
//recording or playing back from
pid_t ktest_fork(enum KTEST_FORK which){
  enum kTestMode ktest_mode = arg_ktest_mode;
  if (ktest_mode == KTEST_NONE){
    pid_t pid = fork();
    return pid;
  } else if(arg_ktest_mode == KTEST_RECORD){
    pid_t pid = fork();
    assert(pid >= 0);
    //This is the case where we no longer wish to record.
    if((pid != 0 && which == CHILD) || (pid == 0 && which == PARENT)){
      ktest_set_mode_none();
      return pid;
    }else if ((pid == 0 && which == CHILD) || (pid != 0 && which == PARENT)) {
      //Keep recording.
      return pid;
    } else {
      perror("ktest_fork error - should never get here");
      exit(4);
    }
  } else if (arg_ktest_mode == KTEST_PLAYBACK){
    if(which == PARENT){ //we recorded the parent
      //return a positive non-0 value.
      //Note: we assume there is no communication between
      //parent and child in the recorded case.  If there is,
      //then we're in trouble.
      return KTEST_FORK_DUMMY_CHILD_PID;
    } else { //we recorded the child, return current pid.
      //not guarenteed to be the same as when recorded.
      return 0;
    }
  } else {
    perror("ktest_fork error - should never get here");
    exit(4);
  }
}
#endif

int ktest_pipe(int pipefd[2]){
  int ret = pipe(pipefd);
  assert(ret == 0); //assume success
  if((arg_ktest_mode == KTEST_RECORD) || (arg_ktest_mode == KTEST_PLAYBACK)) {
    insert_ktest_sockfd(pipefd[0]);
    insert_ktest_sockfd(pipefd[1]);
  }
  return ret;
}

int ktest_socketpair(int domain, int type, int protocol, int sv[2]){
  int ret = socketpair(domain, type, protocol, sv);
  assert(ret == 0); //assume success
  if((arg_ktest_mode == KTEST_RECORD) || (arg_ktest_mode == KTEST_PLAYBACK)) {
    insert_ktest_sockfd(sv[0]);
    insert_ktest_sockfd(sv[1]);
  }
  return ret;
}

int ktest_open(const char *path, int oflag){
  int fd = open(path, oflag);
  assert(fd >= 0);
  if((arg_ktest_mode == KTEST_RECORD) || (arg_ktest_mode == KTEST_PLAYBACK)) {
    insert_ktest_sockfd(fd);
  }
  return fd;
}

int ktest_openpty(int *ptyfd, int *ttyfd, char *name, const struct termios *termp, const struct winsize *winp)
{
  //We're assuming that arg_ktest_mode is consistent with KTest.c's ktest_mode.
  enum kTestMode ktest_mode = arg_ktest_mode;
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

