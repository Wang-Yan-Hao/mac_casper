#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mac.h>
#include <errno.h>
#include <time.h>

#include <sys/nv.h>
#include <libcasper.h>
#include <casper/cap_dns.h>

#define ITERATIONS 2000

int main() {
    //const char *hostname = "www.google.com";
    const char *hostname = "freebsd.org";
    //const char *ip = "1.1.1.1";
    const char *ip = "96.47.72.84";
    struct addrinfo hints, *res;
    struct sockaddr_in sa;
    struct in_addr addr;
    char host[NI_MAXHOST];

    cap_channel_t *cap_casper;
    cap_casper = cap_init();
    if (cap_casper == NULL) {
        printf("Error\n");
    }

    cap_channel_t *cap_net;
    cap_net = cap_service_open(cap_casper, "system.dns");
    if (cap_net == NULL) {
        printf("Error\n");
        return 0;
    }

    struct timespec start, end;
    double elapsed;

    // Measure getaddrinfo
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        int status = cap_getaddrinfo(cap_net, hostname, NULL, &hints, &res);
        if (status != 0) {
            printf("getaddrinfo failed: %s\n", gai_strerror(status));
            return -1;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    freeaddrinfo(res);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("getaddrinfo took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // Measure getnameinfo
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sa.sin_addr);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        int status = cap_getnameinfo(cap_net, (struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, 0);
        if (status != 0) {
            printf("getnameinfo failed: %s\n", gai_strerror(status));
            return -1;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("getnameinfo took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // Measure gethostbyname
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        struct hostent *host_entry = cap_gethostbyname(cap_net, hostname);
        if (host_entry == NULL) {
            printf("gethostbyname failed: %s\n", hstrerror(h_errno));
            return -1;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("gethostbyname took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // Measure gethostbyname2
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        struct hostent *host_entry = cap_gethostbyname2(cap_net, hostname, AF_INET);
        if (host_entry == NULL) {
            printf("gethostbyname2 failed: %s\n", hstrerror(h_errno));
            return -1;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("gethostbyname2 took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // Measure gethostbyaddr
    inet_pton(AF_INET, ip, &addr);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        struct hostent *host_entry = cap_gethostbyaddr(cap_net, &addr, sizeof(addr), AF_INET);
        if (host_entry == NULL) {
            printf("gethostbyaddr failed: %s\n", hstrerror(h_errno));
            return -1;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("gethostbyaddr took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    return 0;
}
