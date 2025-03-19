#define WITH_CASPER
// Casper
#include	<sys/nv.h>
#include	<libcasper.h>
#include	<casper/cap_dns.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <fcntl.h>
#include <unistd.h>

#include	<sys/mac.h>


#include <errno.h>


void test_getaddrinfo(cap_channel_t *cap_net, const char *hostname) {
    struct addrinfo hints, *res, *p;
    char ipstr[INET6_ADDRSTRLEN];

    printf("Testing cap_getaddrinfo for %s:\n", hostname);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (cap_getaddrinfo(cap_net, hostname, NULL, &hints, &res) != 0) {
        perror("cap_getaddrinfo");
        return;
    }


    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;
        const char *ipver;

        if (p->ai_family == AF_INET) {
            addr = &(((struct sockaddr_in *)p->ai_addr)->sin_addr);
            ipver = "IPv4";
        } else {
            addr = &(((struct sockaddr_in6 *)p->ai_addr)->sin6_addr);
            ipver = "IPv6";
        }

        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        printf("  %s: %s\n", ipver, ipstr);
    }

    freeaddrinfo(res);
}

void test_getnameinfo(cap_channel_t *cap_net, const char *ip) {
    struct sockaddr_in sa;
    char host[NI_MAXHOST];

    printf("\nTesting cap_getnameinfo for %s:\n", ip);

    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sa.sin_addr);

    if (cap_getnameinfo(cap_net, (struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, 0) != 0) {
        perror("cap_getnameinfo");
        return;
    }

    printf("  Hostname: %s\n", host);
}

void test_gethostbyname(cap_channel_t *cap_net, const char *hostname) {
    struct hostent *he;

    printf("\nTesting cap_gethostbyname for %s:\n", hostname);

    if ((he = cap_gethostbyname(cap_net, hostname)) == NULL) {
        herror("cap_gethostbyname");
        return;
    }

    for (int i = 0; he->h_addr_list[i] != NULL; i++) {
        printf("  IP: %s\n", inet_ntoa(*(struct in_addr *)he->h_addr_list[i]));
    }
}

void test_gethostbyname2(cap_channel_t *cap_net, char *hostname, int family) {
    struct hostent *he;

    printf("\nTesting cap_gethostbyname2 for %s (family: %s):\n", hostname, family == AF_INET ? "IPv4" : "IPv6");

    if ((he = cap_gethostbyname2(cap_net, hostname, family)) == NULL) {
        herror("cap_gethostbyname2");
        return;
    }

    for (int i = 0; he->h_addr_list[i] != NULL; i++) {
        char ipstr[INET6_ADDRSTRLEN];
        inet_ntop(family, he->h_addr_list[i], ipstr, sizeof(ipstr));
        printf("  IP: %s\n", ipstr);
    }
}

void test_gethostbyaddr(cap_channel_t *cap_net, const char *ip) {
    struct in_addr addr;
struct hostent *he;

    printf("\nTesting cap_gethostbyaddr for %s:\n", ip);

    inet_pton(AF_INET, ip, &addr);

    if ((he = cap_gethostbyaddr(cap_net, &addr, sizeof(addr), AF_INET)) == NULL) {
        herror("cap_gethostbyaddr");
        return;
    }

    printf("  Hostname: %s\n", he->h_name);
}

int main() {
    cap_channel_t *cap_casper;
    const char *hostname = "www.google.com";
    const char *ip = "142.250.72.196"; // Replace with an appropriate IP

    /* cap channel */
    cap_casper = cap_init();
    if (cap_casper == NULL) {
        printf("Error\n");
    }
    int abc;
    // scanf("%d", &abc);
    /* open service */
    cap_channel_t *cap_net;
    cap_net = cap_service_open(cap_casper, "system.dns");
    if (cap_net == NULL) {
        printf("Error\n");
        return 0;
    }
    // scanf("%d", &abc);

    printf("test_getaddrinfo\n");
    test_getaddrinfo(cap_net, hostname);


    test_getnameinfo(cap_net, ip);
    // test_gethostbyname(cap_net, hostname);
    // test_gethostbyname2(cap_net, hostname, AF_INET);
    // test_gethostbyaddr(cap_net, ip);

    // struct addrinfo *res;
    // int ret;
    // ret = cap_getaddrinfo(cap_net, "freebsd.org", "80", NULL, &res);
    // if (ret != 0) {
    //     printf("Error\n");
    // }

        printf("cap_casper close\n");
    cap_close(cap_casper);
    // scanf("%d", &abc);

    printf("cap_net close\n");
    cap_close(cap_net);
    // scanf("%d", &abc);

;

    printf("Main function finish\n");
    return 0;
}
