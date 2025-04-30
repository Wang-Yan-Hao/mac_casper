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

#define ITERATIONS 1000

int main() {
    const char *hostname = "www.google.com";
    const char *ip = "142.250.72.196";
    struct addrinfo hints, *res;
    struct sockaddr_in sa;
    struct in_addr addr;
    char host[NI_MAXHOST];

        struct timespec start, end;
    double elapsed;


#ifdef MAC
    printf("I used mac label.\n");
    clock_gettime(CLOCK_MONOTONIC, &start);


    mac_t mac_label;
    const char *label = "casper/dns";
    for (int i = 0; i < ITERATIONS*200; i++) {

        if (mac_from_text(&mac_label, label) != 0) {
            printf("Failed to convert label from text\n");
            return -1;
        }


        if (mac_set_proc(mac_label) != 0) {
            printf("Failed to set MAC label on process: %s\n", strerror(errno));
            mac_free(mac_label);
            return -1;
        }
    }
    mac_free(mac_label);

    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("mac_set_proc have %f seconds for %d iterations\n", elapsed/200, ITERATIONS);
#endif


    // Measure getaddrinfo
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        int status = getaddrinfo(hostname, NULL, &hints, &res);
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
        int status = getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, 0);
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
        struct hostent *host_entry = gethostbyname(hostname);
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
        struct hostent *host_entry = gethostbyname2(hostname, AF_INET);
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
        struct hostent *host_entry = gethostbyaddr(&addr, sizeof(addr), AF_INET);
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
