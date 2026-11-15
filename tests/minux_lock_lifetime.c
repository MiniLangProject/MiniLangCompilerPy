/* Copyright 2026 Nils Kopal. Apache-2.0. Cross-process flock lifetime tests. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
extern int mlc_flock(int, int);
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "lock test failed at line %d errno=%d\n", __LINE__,      \
              errno);                                                          \
      return 1;                                                                \
    }                                                                          \
  } while (0)
int main(void) {
  const char *path = "/tmp/minilang-lock-lifetime";
  int a = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
  CHECK(a >= 0);
  int b = open(path, O_RDWR);
  CHECK(b >= 0);
  CHECK(mlc_flock(a, 2 | 4) == 0);
  const char *alias="/tmp/minilang-lock-alias";
  unlink(alias);
  CHECK(link(path,alias)==0);
  int alias_fd=open(alias,O_RDWR);
  CHECK(alias_fd>=0&&mlc_flock(alias_fd,1|4)==-1&&errno==EAGAIN);
  CHECK(close(alias_fd)==0&&unlink(alias)==0);
  int duplicate = dup(a);
  CHECK(duplicate >= 0);
  CHECK(close(a) == 0);
  CHECK(mlc_flock(b, 1 | 4) == -1 && errno == EAGAIN);
  CHECK(close(duplicate) == 0);
  CHECK(mlc_flock(b, 2 | 4) == 0);
  CHECK(mlc_flock(b, 8) == 0);
  int ready[2], release[2];
  CHECK(pipe(ready) == 0 && pipe(release) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    close(ready[0]);
    close(release[1]);
    close(b);
    int owned = open(path, O_RDWR);
    if (owned < 0 || mlc_flock(owned, 2 | 4))
      _exit(2);
    char c = 'R';
    if (write(ready[1], &c, 1) != 1 || read(release[0], &c, 1) != 1)
      _exit(3);
    // _exit must release the final description without an explicit unlock.
    usleep(50000);
    _exit(0);
  }
  close(ready[1]);
  close(release[0]);
  char c;
  CHECK(read(ready[0], &c, 1) == 1);
  CHECK(mlc_flock(b, 2 | 4) == -1 && errno == EAGAIN);
  CHECK(write(release[1], "X", 1) == 1);
  CHECK(mlc_flock(b,2)==0);
  int status;
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
  CHECK(mlc_flock(b, 2 | 4) == 0);
  CHECK(close(b) == 0);
  unlink(path);
  puts("MINUX_LOCK_DUP_FORK_EXIT_OK");
  return 37;
}
