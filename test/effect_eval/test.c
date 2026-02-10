/*
 * fork_exec_permanent_sh.c
 *
 * Parent exits immediately.
 * Child execs a permanent /bin/sh.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int
main(void)
{
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        /* Child */
        printf("[child] before execve, pid=%d\n", getpid());

        char *argv[] = {
            "/bin/sh",
            NULL
        };

        char *envp[] = {
            "PATH=/bin:/usr/bin",
            NULL
        };

        execve("/bin/sh", argv, envp);

        /* execve only returns on error */
        perror("execve");
        _exit(1);
    }

    /* Parent returns immediately */
    printf("[parent] pid=%d, child pid=%d (returning immediately)\n",
           getpid(), pid);

    return 0;
}
