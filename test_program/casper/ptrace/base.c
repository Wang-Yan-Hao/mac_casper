#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/reg.h>
#include <sys/ptrace.h>


#include <sys/capsicum.h>

int main() {
    pid_t child_pid = fork();

    if (child_pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (child_pid == 0) {
        ptrace(PT_TRACE_ME, 0, NULL, 0);
        execl("/bin/ls", "ls", NULL);
        return 0;
    } else {
        int status;

        if (cap_enter() != 0) {
            fprintf (stderr, "cap_enter failed.\n");
            exit (EXIT_FAILURE);
        }

        while (1) {
            wait(&status);
            if(WIFEXITED(status))
                break;

            printf("Child made a system call\n");
            if (ptrace(PT_SYSCALL, child_pid, (caddr_t) 1, 0) == -1) {
                printf("ptrace failed\n");
                break;
            }
        }

    }
    return 0;
}
