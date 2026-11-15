/* Copyright 2026 Nils Kopal. Apache-2.0. Test real guest exit status. */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Compare the actual guest-built executables, including all metadata. */
static int compare_files(const char *first, const char *second) {
    int left = open(first, O_RDONLY), right = open(second, O_RDONLY);
    unsigned char a[4096], b[4096];
    unsigned long long total = 0;
    int result = 1;
    if (left < 0 || right < 0) goto done;
    for (;;) {
        ssize_t count = read(left, a, sizeof(a));
        if (count < 0) goto done;
        size_t actual = 0;
        while (actual < (size_t)count) {
            ssize_t next = read(right, b + actual, (size_t)count - actual);
            if (next <= 0) goto done;
            actual += (size_t)next;
        }
        if (memcmp(a, b, (size_t)count) != 0) goto done;
        total += (unsigned long long)count;
        if (count == 0) {
            if (read(right, b, 1) != 0 || total == 0) goto done;
            result = 0;
            break;
        }
    }
done:
    if (left >= 0 && close(left) != 0) result = 1;
    if (right >= 0 && close(right) != 0) result = 1;
    if (result == 0) {
        printf("MINILANG_FIXED_POINT_OK bytes=%llu\n", total);
        puts("MINILANG_GUEST_PROGRAM_PASSED");
    } else puts("MINILANG_FIXED_POINT_FAILED");
    return result;
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "--compare") == 0)
        return compare_files(argv[2], argv[3]);
    if (argc < 3) return 125;
    int expected = atoi(argv[1]);
    pid_t child = fork();
    if (child == 0) {
        char *args[] = {argv[2], "alpha", "beta", 0};
        execv(argv[2], argc == 3 ? args : argv + 2);
        _exit(126);
    }
    int status = 0;
    pid_t waited;
    if (child < 0) {
        puts("MINILANG_GUEST_PROGRAM_FAILED: fork");
        return 125;
    }
    /* Keep the test's wait independent of terminal/signal wakeups. Only an
       actual reap of this child can supply the accepted exit status. */
    do {
        waited = waitpid(child, &status, WNOHANG);
        if (waited == 0) usleep(1000);
    } while (waited == 0 || (waited < 0 && errno == EINTR));
    if (waited != child) {
        printf("MINILANG_GUEST_PROGRAM_FAILED: waitpid=%d child=%d errno=%d\n", waited, child, errno);
        return 125;
    }
    printf("MINILANG_STATUS=%d EXPECTED=%d\n", WEXITSTATUS(status), expected);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != expected) {
        puts("MINILANG_GUEST_PROGRAM_FAILED: exit status");
        return 1;
    }
    puts("MINILANG_GUEST_PROGRAM_PASSED");
    return 0;
}
