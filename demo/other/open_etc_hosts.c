#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <string.h>

#include	<sys/socket.h>
int main() {
    /*
    // Test write syscall
    int fd = open("/etc/hosts", O_RDONLY, 0644);
    if (fd == -1) {
        perror("open for write failed");
        exit(EXIT_FAILURE);
    }

    // Test execve syscall
    char *argv[] = {"/bin/ls", NULL};
    char *envp[] = {NULL};

    if (execve("/bin/ls", argv, envp) == -1) {
        perror("execve failed");
        exit(EXIT_FAILURE);
    }
    */

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd >= 0) {
        printf("Socket created successfully\n");
        close(sockfd);
    } else {
        perror("Socket creation failed");
    }

    return 0;
}
