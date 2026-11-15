/* Copyright 2026 Nils Kopal. Apache-2.0.
 * Exercise a managed MiniGui app using actual MinUX desktop pipes. */
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static char frame[65536];
static int read_frame(int fd, const char *needle) {
  size_t used = 0;
  int frames = 0;
  while (frames < 100) {
    struct pollfd p = {fd, POLLIN, 0};
    if (poll(&p, 1, 30000) <= 0)
      return 0;
    char ch;
    if (read(fd, &ch, 1) != 1)
      return 0;
    if (used + 1 >= sizeof(frame))
      return 0;
    frame[used++] = ch;
    frame[used] = 0;
    if (used >= 5 && !memcmp(frame + used - 5, "\nEND\n", 5)) {
      if (strstr(frame, "BEGIN\n") && strstr(frame, needle))
        return 1;
      used = 0;
      frames++;
    }
  }
  return 0;
}
static int send_command(int fd, const char *text) {
  size_t n = strlen(text);
  return write(fd, text, n) == (ssize_t)n;
}
int main(void) {
  int input[2], output[2], status = 0, result = 1;
  if (pipe(input) || pipe(output))
    return 1;
  pid_t child = fork();
  if (child == 0) {
    dup2(input[0], 0);
    dup2(output[1], 1);
    close(input[0]);
    close(input[1]);
    close(output[0]);
    close(output[1]);
    char *args[] = {"/home/user/fixtures/gui-app.elf", 0};
    execv(args[0], args);
    _exit(126);
  }
  if (child < 0)
    return 2;
  close(input[0]);
  close(output[1]);
  if (!read_frame(output[0], "TEXT Press me\n"))
    goto done;
  if (!send_command(input[1], "TEXT 1003 edited\nACT 1002\n"))
    goto done;
  if (!read_frame(output[0], "TEXT Confirm\n") ||
      !strstr(frame, "TEXT clicked:edited\n"))
    goto done;
  if (!send_command(input[1], "ACT 2147418122\n"))
    goto done;
  if (!read_frame(output[0], "TEXT confirmed\n"))
    goto done;
  if (!read_frame(output[0], "TEXT /tmp/minilang-video-"))
    goto done;
  char *path = strstr(frame, "TEXT /tmp/minilang-video-") + 5,
       *end = strchr(path, '\n');
  if (!end)
    goto done;
  *end = 0;
  int bitmap = open(path, O_RDONLY);
  unsigned char header[70];
  if (bitmap < 0)
    goto done;
  ssize_t bytes = read(bitmap, header, sizeof(header));
  close(bitmap);
  if (bytes != 70 || header[0] != 'B' || header[1] != 'M' || header[18] != 2 ||
      header[22] != 2 || header[28] != 24)
    goto done;
  if (!send_command(input[1], "CLOSE\n"))
    goto done;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 37)
    goto done;
  child = -1;
  puts("MINUX_GUI_EVENTS_DIALOG_VIDEO_FRAME_OK");
  result = 37;
done:
  if (result != 37)
    fprintf(stderr, "MinUX GUI driver failed; last frame: %s\n", frame);
  if (child > 0) {
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
  }
  close(input[1]);
  close(output[0]);
  return result;
}
