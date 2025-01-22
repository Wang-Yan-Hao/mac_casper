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

void test_getaddrinfo(const char *hostname) {
    struct addrinfo hints, *res, *p;
    char ipstr[INET6_ADDRSTRLEN];

    printf("Testing getaddrinfo for %s:\n", hostname);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        perror("getaddrinfo");
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

void test_getnameinfo(const char *ip) {
    struct sockaddr_in sa;
    char host[NI_MAXHOST];

    printf("\nTesting getnameinfo for %s:\n", ip);

    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sa.sin_addr);

    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, 0) != 0) {
        perror("getnameinfo");
        return;
    }

    printf("  Hostname: %s\n", host);
}

void test_gethostbyname(const char *hostname) {
    struct hostent *he;

    printf("\nTesting gethostbyname for %s:\n", hostname);

    if ((he = gethostbyname(hostname)) == NULL) {
        herror("gethostbyname");
        return;
    }

    for (int i = 0; he->h_addr_list[i] != NULL; i++) {
        printf("  IP: %s\n", inet_ntoa(*(struct in_addr *)he->h_addr_list[i]));
    }
}

void test_gethostbyname2(const char *hostname, int family) {
    struct hostent *he;

    printf("\nTesting gethostbyname2 for %s (family: %s):\n", hostname, family == AF_INET ? "IPv4" : "IPv6");

    if ((he = gethostbyname2(hostname, family)) == NULL) {
        herror("gethostbyname2");
        return;
    }

    for (int i = 0; he->h_addr_list[i] != NULL; i++) {
        char ipstr[INET6_ADDRSTRLEN];
        inet_ntop(family, he->h_addr_list[i], ipstr, sizeof(ipstr));
        printf("  IP: %s\n", ipstr);
    }
}

void test_gethostbyaddr(const char *ip) {
    struct in_addr addr;
    struct hostent *he;

    printf("\nTesting gethostbyaddr for %s:\n", ip);

    inet_pton(AF_INET, ip, &addr);

    if ((he = gethostbyaddr(&addr, sizeof(addr), AF_INET)) == NULL) {
        herror("gethostbyaddr");
        return;
    }

    printf("  Hostname: %s\n", he->h_name);
}

int main() {
    const char *hostname = "www.google.com";
    const char *ip = "142.250.72.196";

    mac_t mac_label;
    const char *label = "casper/dns";
    // const char *label = "biba/low";

    // Convert the text label to the internal mac_t format
    if (mac_from_text(&mac_label, label) != 0) {
        printf("Failed to convert label from text\n");
        return -1;
    }

    int ret = 0;
    // Apply the label to the current process
    if ((ret = mac_set_proc(mac_label)) != 0) {
        printf("Error: %s\n", strerror(errno));
        printf("Failed to set MAC label on process\n");
        mac_free(mac_label);
        return -1;
    }

    mac_free(mac_label);

    /* Test function in service "casper_dns" */
    test_getaddrinfo(hostname);
    test_getnameinfo(ip);
    test_gethostbyname(hostname);
    test_gethostbyname2(hostname, AF_INET);
    test_gethostbyaddr(ip);

    /* Test open other file will failed */
    int fd = open("test.txt", O_RDONLY);
    if (fd == -1) {
        printf("Open failed\n");
    } else {
        printf("Open success\n");
    }

    /* Test open other file will failed */
    if (chdir("/") == -1) {
        printf("Chdir failed\n");
    } else {
        printf("Chdir success\n");
    }

    return 0;
}
