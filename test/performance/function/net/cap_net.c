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
#include <errno.h>
#include <time.h>

#include <sys/nv.h>
#include <libcasper.h>
#include <casper/cap_net.h>

#if defined(__aarch64__)
    #define ITER_BIND 10000
	#define ITER_CONNECT 250
#elif defined(__amd64__)
    #define ITER_BIND 70000
	#define ITER_CONNECT 250
#else
    #define ITER_BIND 1
	#define ITER_CONNECT 1
#endif

int main() {
    const char *hostname = "freebsd.org";
    const char *ip = "127.0.0.1"; // Test on local
    int port = 8080;

    struct sockaddr_in sa;
    struct timespec start, end;
    double elapsed;

    cap_channel_t *cap_casper = cap_init();
    if (cap_casper == NULL) {
        perror("cap_init failed");
        return -1;
    }

    cap_channel_t *cap_net = cap_service_open(cap_casper, "system.net");
    if (cap_net == NULL) {
        perror("cap_service_open failed");
        cap_close(cap_casper);
        return -1;
    }
    cap_close(cap_casper);

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip, &sa.sin_addr);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITER_BIND; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        // Set SO_REUSEADDR to avoid port occupy
        int opt = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        int status = cap_bind(cap_net, s, (struct sockaddr *)&sa, sizeof(sa));
        if (status != 0 && errno != EADDRINUSE) {
            perror("cap_bind failed");
        }
        close(s);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("cap_bind         took %f seconds\n", elapsed);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITER_CONNECT; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);

        cap_connect(cap_net, s, (struct sockaddr *)&sa, sizeof(sa));

        close(s);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("cap_connect      took %f seconds\n", elapsed);

    cap_close(cap_net);
    return 0;
}
