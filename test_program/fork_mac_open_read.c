#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <string.h>

#define CASPER_DNS_UID 1002

void child_process() {
    if (setuid(CASPER_DNS_UID) == -1) {
        perror("setuid failed");
        exit(EXIT_FAILURE);
    }

    // Test write syscall
    // int fd = open("/etc/hosts", O_RDONLY, 0644);
    // if (fd == -1) {
    //     perror("open for write failed");
    //     exit(EXIT_FAILURE);
    // }

    // Test execve syscall
    char *argv[] = {"/bin/ls", NULL};
    char *envp[] = {NULL};

    if (execve("/bin/ls", argv, envp) == -1) {
        perror("execve failed");
        exit(EXIT_FAILURE);
    }
}

int main() {
    pid_t pid = fork();

    if (pid == -1) {
        perror("fork failed");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        // In the child process
        child_process();
    } else {
        // In the parent process, wait for child to finish
        wait(NULL);
        printf("Child process finished\n");
    }

    return 0;
}

