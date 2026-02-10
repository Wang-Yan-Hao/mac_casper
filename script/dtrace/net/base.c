#define WITH_CASPER

#include <sys/nv.h>
#include <libcasper.h>
#include <casper/cap_net.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/**
 * Test 1: Connection via system.net (Client Mode)
 * Function: cap_connect (Exclusive to system.net)
 */
void test_cap_connect(cap_channel_t *cap_net, const char *ip, int port) {
    int sockfd;
    struct sockaddr_in servaddr;
    int ret;

    printf("\n--- Testing cap_connect to %s:%d ---\n", ip, port);

    /* 1. Create Socket
     * Even in a sandbox, the client usually creates the FD,
     * while the service performs the privileged connect() call.
     */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &servaddr.sin_addr);

    /* 2. Request Casper to perform the connection
     * This triggers the connect() syscall inside the system.net service process.
     */
    printf("Requesting cap_connect through Casper...\n");
    ret = cap_connect(cap_net, sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    if (ret == 0) {
        printf("  Success! Connected to remote server via Casper.\n");
    } else {
        perror("  cap_connect failed");
    }

    close(sockfd);
}

/**
 * Test 2: Binding via system.net (Server Mode)
 * Function: cap_bind (Exclusive to system.net)
 */
void test_cap_bind(cap_channel_t *cap_net, int port) {
    int listenfd;
    struct sockaddr_in servaddr;
    int ret;

    printf("\n--- Testing cap_bind on port %d ---\n", port);

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        perror("Socket creation failed");
        return;
    }

    /* Set SO_REUSEADDR to allow immediate reuse of the port */
    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);

    /* Request Casper to perform the bind
     * This triggers the bind() syscall inside the system.net service process.
     */
    printf("Requesting cap_bind through Casper...\n");
    ret = cap_bind(cap_net, listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    if (ret == 0) {
        printf("  Success! Socket bound to port %d.\n", port);
        /* Verify by attempting to listen */
        if (listen(listenfd, 5) == 0) {
            printf("  Socket is now listening (verification successful).\n");
        }
    } else {
        perror("  cap_bind failed");
    }

    close(listenfd);
}

/**
 * Test 3: Name Resolution via system.net
 * Function: cap_getaddrinfo (Supported by both net and dns)
 */
void test_cap_getaddrinfo(cap_channel_t *cap_net, const char *hostname) {
    struct addrinfo hints, *res, *p;
    char ipstr[INET6_ADDRSTRLEN];

    printf("\n--- Testing cap_getaddrinfo (via system.net) for %s ---\n", hostname);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    /* system.net's resolver is subject to cap_net_limit_name2addr restrictions */
    if (cap_getaddrinfo(cap_net, hostname, NULL, &hints, &res) != 0) {
        perror("cap_getaddrinfo failed");
        return;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;
        const char *ipver;

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        printf("  %s: %s\n", ipver, ipstr);
    }

    freeaddrinfo(res);
}

int main() {
    cap_channel_t *cap_casper;
    cap_channel_t *cap_net;

    /* Test Configuration */
    const char *remote_ip = "8.8.8.8";   /* Google DNS */
    const char *hostname = "www.freebsd.org";
    int connect_port = 53;              /* DNS TCP port */
    int bind_port = 8080;               /* Local port for binding */

    printf("PID: %d. Press ENTER to initialize (Attach DTrace to trace syscalls)...\n", getpid());
    getchar();

    /* 1. Initialize Casper Core */
    cap_casper = cap_init();
    if (cap_casper == NULL) {
        perror("cap_init failed");
        exit(1);
    }

    /* 2. Open the 'system.net' service */
    cap_net = cap_service_open(cap_casper, "system.net");
    if (cap_net == NULL) {
        perror("cap_service_open failed");
        cap_close(cap_casper);
        exit(1);
    }

    /* Close main casper channel; we only need the service channel now */
    cap_close(cap_casper);

    printf("Service 'system.net' is open. Executing baseline functions...\n");

    /* 3. Execute Baseline Tests */
    test_cap_getaddrinfo(cap_net, hostname);
    test_cap_connect(cap_net, remote_ip, connect_port);
    test_cap_bind(cap_net, bind_port);

    /* 4. Finalizing */
    printf("\nAll tests completed. Press ENTER to close channels and exit...\n");
    getchar();

    cap_close(cap_net);
    printf("Finished.\n");

    return 0;
}
