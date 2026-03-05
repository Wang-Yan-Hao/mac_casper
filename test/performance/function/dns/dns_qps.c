#define WITH_CASPER
#define _POSIX_C_SOURCE 200809L

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
#include <signal.h>
#include <sys/time.h>
#include <time.h>

#include <libcasper.h>
#include <casper/cap_dns.h>

double SECONDS = 60.0;

const char *hostname = "freebsd.org";
const char *ip = "96.47.72.84";

cap_channel_t *cap_casper, *cap_net;

int queries = 0;
int seconds_elapsed = 0;
int total_queries = 0;
int running = 1;

int func_index = 0;
char *func[5] = {"cap_getaddrinfo", "cap_getnameinfo", "cap_gethostbyname", "cap_gethostbyname2", "cap_gethostbyaddr"};

void timer_handler(int sig) {
    printf("%s Second %d -> %d queries\n",func[func_index], seconds_elapsed + 1, queries);
    total_queries += queries;
    queries = 0;
    seconds_elapsed++;
    if (seconds_elapsed >= SECONDS) {
        running = 0;
		func_index++;
    }
}

void test_getaddrinfo() {
    printf("\n=== Testing cap_getaddrinfo for %lfs ===\n", SECONDS);

    queries = 0;
    seconds_elapsed = 0;
    total_queries = 0;
    running = 1;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    while (running) {
        int status = cap_getaddrinfo(cap_net, hostname, NULL, &hints, &res);
        if (status == 0) {
            queries++;
            freeaddrinfo(res);
        }
    }

    double avg_qps = (double)total_queries / SECONDS;
    printf("Total queries: %d\n", total_queries);
    printf("Average QPS (cap_getaddrinfo): %.2f\n", avg_qps);
}

void test_getnameinfo() {
    printf("\n=== Testing cap_getnameinfo for %lfs ===\n", SECONDS);

    queries = 0;
    seconds_elapsed = 0;
    total_queries = 0;
    running = 1;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    // Get an address first
    if (cap_getaddrinfo(cap_net, hostname, NULL, &hints, &res) != 0) {
        perror("cap_getaddrinfo (prep for getnameinfo)");
        exit(1);
    }

    char host[NI_MAXHOST];
    while (running) {
        int status = cap_getnameinfo(cap_net, res->ai_addr, res->ai_addrlen,
                                     host, sizeof(host),
                                     NULL, 0, NI_NUMERICSERV);
        if (status == 0) {
            queries++;
        }
    }

    freeaddrinfo(res);

    double avg_qps = (double)total_queries / SECONDS;
    printf("Total queries: %d\n", total_queries);
    printf("Average QPS (cap_getnameinfo): %.2f\n", avg_qps);
}

void test_gethostbyname() {
    printf("\n=== Testing cap_gethostbyname for %lfs ===\n", SECONDS);
    cap_channel_t *cap_net_local = cap_service_open(cap_casper, "system.dns");
    if (!cap_net_local) { perror("cap_service_open"); exit(1); }

    queries = 0;
    seconds_elapsed = 0;
    total_queries = 0;
    running = 1;

    while (running) {
        struct hostent *he = cap_gethostbyname(cap_net_local, hostname);
        if (he != NULL) {
            queries++;
        }
    }

    double avg_qps = (double)total_queries / SECONDS;
    printf("Total queries: %d\n", total_queries);
    printf("Average QPS (cap_gethostbyname): %.2f\n", avg_qps);
	cap_close(cap_net_local);
}

void test_gethostbyname2() {
    printf("\n=== Testing cap_gethostbyname2 for %lfs ===\n", SECONDS);
    cap_channel_t *cap_net_local = cap_service_open(cap_casper, "system.dns");
    if (!cap_net_local) { perror("cap_service_open"); exit(1); }

    queries = 0;
    seconds_elapsed = 0;
    total_queries = 0;
    running = 1;

    while (running) {
        struct hostent *he = cap_gethostbyname2(cap_net_local, hostname, AF_INET);
        if (he != NULL) {
            queries++;
        }
    }

    double avg_qps = (double)total_queries / SECONDS;
    printf("Total queries: %d\n", total_queries);
    printf("Average QPS (cap_gethostbyname2): %.2f\n", avg_qps);
	cap_close(cap_net_local);
}

void test_gethostbyaddr() {
    printf("\n=== Testing cap_gethostbyaddr for %lfs ===\n", SECONDS);
    cap_channel_t *cap_net_local = cap_service_open(cap_casper, "system.dns");
    if (!cap_net_local) { perror("cap_service_open"); exit(1); }

    queries = 0;
    seconds_elapsed = 0;
    total_queries = 0;
    running = 1;

    struct in_addr addr;
	inet_pton(AF_INET, ip, &addr);

    while (running) {
        struct hostent *he = cap_gethostbyaddr(cap_net_local, &addr, sizeof(addr), AF_INET);
        if (he != NULL) {
            queries++;
        }
    }

    double avg_qps = (double)total_queries / SECONDS;
    printf("Total queries: %d\n", total_queries);
    printf("Average QPS (cap_gethostbyaddr): %.2f\n", avg_qps);
	cap_close(cap_net_local);
}

int main() {
    cap_casper = cap_init();
    if (!cap_casper) { perror("cap_init"); exit(1); }

    cap_net = cap_service_open(cap_casper, "system.dns");
    if (!cap_net) { perror("cap_service_open"); exit(1); }

    struct sigaction sa;
    sa.sa_handler = timer_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        perror("sigaction"); exit(1);
    }

	// 1 second
    struct itimerval timer;
    timer.it_value.tv_sec = 1;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 1;
    timer.it_interval.tv_usec = 0;
    if (setitimer(ITIMER_REAL, &timer, NULL) == -1) {
        perror("setitimer"); exit(1);
    }

    // Run tests
    test_getaddrinfo();
    test_getnameinfo();
	test_gethostbyname();
	test_gethostbyname2();
	test_gethostbyaddr();

    return 0;
}

