/* Copyright 2026 Nils Kopal. Apache-2.0. Verify echo-safe input on a real PTY.
 */
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
extern int64_t mlc_read_secret(const char *, unsigned char *, size_t);
struct terminal {
  uint32_t flags;
  unsigned char interrupt, eof, kill, erase;
};
static int until(int fd, char *output, size_t capacity, const char *marker) {
  size_t used = 0;
  output[0] = 0;
  while (used + 1 < capacity) {
    struct pollfd p = {fd, POLLIN, 0};
    if (poll(&p, 1, 30000) <= 0)
      return 0;
    if (read(fd, output + used, 1) != 1)
      return 0;
    output[++used] = 0;
    if (strstr(output, marker))
      return 1;
  }
  return 0;
}
static int probe(int overflow) {
  struct {
    int master, slave, index;
    unsigned reserved;
  } pty = {0};
  register int64_t result __asm__("rax") = 444;
  __asm__ volatile("int $0x80"
                   : "+a"(result)
                   : "D"(&pty)
                   : "rcx", "r11", "memory", "cc");
  if (result)
    return 0;
  pid_t child = fork();
  int status = 0, ok = 0;
  if (child == 0) {
    close(pty.master);
    dup2(pty.slave, 0);
    dup2(pty.slave, 1);
    close(pty.slave);
    struct terminal before, after;
    unsigned char output[16];
    memset(output, 0xcc, sizeof(output));
    if (ioctl(0, 0x5401, &before))
      _exit(1);
    int64_t size =
        mlc_read_secret("PROMPT:", output, overflow ? 3 : sizeof(output));
    if (ioctl(0, 0x5401, &after) || memcmp(&before, &after, sizeof(before)))
      _exit(2);
    if (overflow) {
      if (size != -1 || output[0] || output[1] || output[2])
        _exit(3);
    } else if (size != 6 || memcmp(output, "secret", 6))
      _exit(4);
    puts("RESTORED");
    _exit(37);
  }
  close(pty.slave);
  if (child < 0) {
    close(pty.master);
    return 0;
  }
  char output[512];
  if (!until(pty.master, output, sizeof(output), "PROMPT:"))
    goto done;
  if (write(pty.master, "secret\n", 7) != 7)
    goto done;
  if (!until(pty.master, output, sizeof(output), "RESTORED") ||
      strstr(output, "secret"))
    goto done;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 37)
    goto done;
  child = -1;
  ok = 1;
done:
  if (child > 0) {
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
  }
  close(pty.master);
  return ok;
}
int main(void) {
  if (!probe(0) || !probe(1))
    return 1;
  puts("MINUX_SECRET_ECHO_RESTORE_OVERFLOW_OK");
  return 37;
}
