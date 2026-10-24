#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program-to-execute>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Target UID for casper_dns (replace with your desired UID)
    uid_t target_uid = 1002;

    printf("Current UID: %d\n", getuid());

    pid_t pid = fork();
    if (pid < 0) {
        perror("Failed to fork");
        return EXIT_FAILURE;
    }

    if (pid == 0) {
        // Child process: attempt to change UID and execute the program
        if (setuid(target_uid) == -1) {
            perror("Failed to set UID");
            exit(EXIT_FAILURE);
        }

        printf("Successfully changed UID to: %d\n", getuid());

        // Execute the specified program
        execvp(argv[1], &argv[1]);

        // If execvp fails
        perror("Failed to execute program");
        exit(EXIT_FAILURE);
    } else {
        // Parent process: wait for the child to complete
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            printf("Child process exited with status: %d\n", WEXITSTATUS(status));
        } else {
            printf("Child process did not exit normally\n");
        }
    }

    return EXIT_SUCCESS;
}

