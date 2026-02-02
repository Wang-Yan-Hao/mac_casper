/* This is a translation of the Perl routine. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <machine/reg.h>
#include <signal.h>

#include <sys/capsicum.h>

int getcall (int pid)
{
    int status;

    struct reg registers;
    status = ptrace (PT_GETREGS, pid, (caddr_t) & registers, 0);
    if (status != 0) {
        return -1;
    }
    return registers.r_rax;
}

void run ()
{
    int status;
    status = ptrace (PT_TRACE_ME, 0, 0, 0);
    if (status != 0) {
        exit (EXIT_FAILURE);
    }
    execl ("/bin/ls", "ls", NULL);
}


int main (int argc, char ** argv) {
    int pid;

    pid = fork ();
    if (pid == -1) {
        fprintf (stderr, "Fork failed: %s\n", strerror (errno));
        exit (EXIT_FAILURE);
    }
    else if (pid == 0) {
        run ();
    }
    else {
        int count = 0;

        if (cap_enter() != 0) {
            fprintf (stderr, "cap_enter failed.\n");
            exit (EXIT_FAILURE);
        }

        if (wait (0) == -1) {
            fprintf (stderr, "Wait failed.\n");
            exit (EXIT_FAILURE);
        }
        while (ptrace (PT_TO_SCE, pid, (caddr_t) 1, 0) == 0) {
            int call;
            int retval;
            if (wait (0) == -1) {
                printf("I leave here bye bye\n");
                break;
            }
            call = getcall (pid);
            if (call == -1) {
                break;
            }
            ptrace (PT_TO_SCX, pid, (caddr_t) 1, 0);
            if (wait (0) == -1) {
                printf("No: I leave here bye bye\n");
                break;
            }
            retval = getcall (pid);
            count++;
            printf ("# %05d %03d return: %X\n", count, call, retval);
        }
        printf ("%d system calls issued.\n", count);
    }
    return 0;
}
