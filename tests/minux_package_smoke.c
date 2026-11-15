/* Copyright 2026 Nils Kopal.
   Licensed under the Apache License, Version 2.0.
   https://www.apache.org/licenses/LICENSE-2.0 */
/* Exercise the compiler, stdlib, runtimes and generator from extracted releases. */
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static int run(char **arguments) {
    pid_t child = fork(), waited;
    int status = 0;
    if (child < 0) return 125;
    if (child == 0) {
        execv(arguments[0], arguments);
        _exit(126);
    }
    do {
        waited = waitpid(child, &status, WNOHANG);
        if (waited == 0) usleep(1000);
    } while (waited == 0 || (waited < 0 && errno == EINTR));
    if (waited != child || !WIFEXITED(status)) return 125;
    return WEXITSTATUS(status);
}

int main(void) {
    char *version[] = {"/home/user/fixtures/compiler/mlc", "--version", 0};
    char *compile[] = {"/home/user/fixtures/compiler/mlc",
        "/home/user/fixtures/compiler/examples/hello.ml", "/home/user/release-hello",
        "--target", "minux-x64", "-I", "/home/user/fixtures/compiler", "--pack", 0};
    char *hello[] = {"/home/user/release-hello", 0};
    char *generator[] = {"/home/user/fixtures/minigui/tools/minigui-minux", "validate",
        "/home/user/fixtures/minigui/examples/hello-gui/app.mson", 0};
    if (run(version) != 0) return 1;
    if (run(compile) != 0) return 2;
    if (run(hello) != 0) return 3;
    if (run(generator) != 0) return 4;
    puts("MINUX_RELEASE_PACKAGE_OK");
    return 37;
}
