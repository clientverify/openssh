#include <openssl/KTest.h>
#include <sys/termios.h>
#include <sys/ioctl.h>

//indicates if we're recording the parent or
//child
//enum KTEST_FORK {PARENT, CHILD};
//pid_t ktest_fork(enum KTEST_FORK which);
int ktest_pipe(int pipefd[2]);
int ktest_open(const char *path, int oflag);
int ktest_openpty(int *ptyfd, int *ttyfd, char *name, const struct termios *termp, const struct winsize *winp);
