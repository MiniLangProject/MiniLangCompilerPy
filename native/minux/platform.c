/* Copyright 2026 Nils Kopal. Apache-2.0. Native MinUX standard-library
 * adapters. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* MinUX libc currently publishes a process-local errno object. Keep that ABI
 * explicit; this function is not a claim that the OS has ELF TLS errno. */
int *mlc_errno_location(void) { return &errno; }

void mlc_explicit_bzero(void *data, size_t bytes) {
  volatile unsigned char *p = data;
  while (bytes--)
    *p++ = 0;
}

/* MinUX's terminal ABI is an eight-byte termios request, not Linux termios.
 * Refuse input unless echo can be disabled, and restore the original mode on
 * every path after changing it. The caller owns and wipes the output buffer. */
int64_t mlc_read_secret(const char *prompt, unsigned char *output,
                        size_t capacity) {
  struct {
    uint32_t flags;
    unsigned char interrupt, eof, kill, erase;
  } original, hidden;
  int fd = open("/dev/tty", O_RDWR);
  size_t count = 0;
  int failed = 0, overflow = 0;
  if (fd < 0 || !prompt || !output) {
    if (fd >= 0)
      close(fd);
    return -1;
  }
  if (ioctl(fd, 0x5401, &original)) {
    close(fd);
    return -1;
  }
  hidden = original;
  hidden.flags = (hidden.flags & ~8U) | 2U;
  if (ioctl(fd, 0x5402, &hidden)) {
    close(fd);
    return -1;
  }
  size_t prompt_length = strlen(prompt), sent = 0;
  while (sent < prompt_length) {
    ssize_t n = write(fd, prompt + sent, prompt_length - sent);
    if (n <= 0) {
      failed = 1;
      break;
    }
    sent += n;
  }
  while (!failed) {
    unsigned char ch;
    ssize_t n = read(fd, &ch, 1);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      failed = 1;
      break;
    }
    if (ch == '\n' || ch == '\r')
      break;
    if (count < capacity)
      output[count++] = ch;
    else
      overflow = 1;
  }
  if (ioctl(fd, 0x5402, &original))
    failed = 1;
  (void)write(fd, "\n", 1);
  if (close(fd))
    failed = 1;
  if (failed || overflow) {
    mlc_explicit_bzero(output, capacity);
    return -1;
  }
  return (int64_t)count;
}

/* FileHandle owns its descriptor. Serialize the seek/read/restore transaction
 * for positional I/O on handles used by MiniLang threads. Native clients must
 * not independently change the position on the same open description. */
static pthread_mutex_t positional_mutex = PTHREAD_MUTEX_INITIALIZER;
static ssize_t positioned(int fd, void *buffer, size_t bytes, int64_t offset,
                          int writing) {
  if (offset < 0 || bytes > 0x7fffffffU) {
    errno = EINVAL;
    return -1;
  }
  pthread_mutex_lock(&positional_mutex);
  off_t original = lseek(fd, 0, SEEK_CUR);
  ssize_t result = -1;
  int saved = errno;
  if (original >= 0 && lseek(fd, offset, SEEK_SET) >= 0) {
    result = writing ? write(fd, buffer, bytes) : read(fd, buffer, bytes);
    saved = errno;
    if (lseek(fd, original, SEEK_SET) < 0) {
      result = -1;
      saved = errno;
    }
  } else
    saved = errno;
  pthread_mutex_unlock(&positional_mutex);
  errno = saved;
  return result;
}
ssize_t mlc_pread(int fd, void *buffer, size_t bytes, int64_t offset) {
  return positioned(fd, buffer, bytes, offset, 0);
}
ssize_t mlc_pwrite(int fd, const void *buffer, size_t bytes, int64_t offset) {
  return positioned(fd, (void *)buffer, bytes, offset, 1);
}

/* The native kernel owns lock lifetime through open-description references.
 * Waiting stays outside the kernel/global VFS lock. A failed conversion retains
 * the caller's old lock; unlocking or final close releases it for all dup refs.
 */
int mlc_flock(int fd, int operation) {
  if ((operation & ~15) || (operation & 11) == 0) {
    errno = EINVAL;
    return -1;
  }
  int requested = operation & ~4;
  if (requested != 1 && requested != 2 && requested != 8) {
    errno = EINVAL;
    return -1;
  }
  for (;;) {
    register int64_t number __asm__("rax") = 73;
    register int64_t descriptor __asm__("rdi") = fd;
    register int64_t op __asm__("rsi") = requested;
    __asm__ volatile("int $0x80"
                     : "+a"(number)
                     : "D"(descriptor), "S"(op)
                     : "rcx", "r11", "memory", "cc");
    if (number == 0)
      return 0;
    if (number != -EAGAIN || (operation & 4)) {
      errno = number < 0 ? -number : EIO;
      return -1;
    }
    if (usleep(10000) && errno == EINTR)
      return -1;
  }
}
