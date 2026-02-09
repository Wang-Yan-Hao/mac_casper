#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/mac.h>
#include <errno.h>
#include <string.h>

#ifndef ITERATIONS
#define ITERATIONS 100000
#endif

#if defined(MAC_DNS)
    #define CURRENT_LABEL "casper/dns"
    #define TEST_TYPE "dns"
#elif defined(MAC_GRP)
    #define CURRENT_LABEL "casper/grp"
    #define TEST_TYPE "grp"
#elif defined(MAC_NETDB)
    #define CURRENT_LABEL "casper/netdb"
    #define TEST_TYPE "netdb"
#elif defined(MAC_PWD)
    #define CURRENT_LABEL "casper/pwd"
    #define TEST_TYPE "pwd"
#elif defined(MAC_SYSCTL)
    #define CURRENT_LABEL "casper/sysctl"
    #define TEST_TYPE "sysctl"
#elif defined(MAC_SYSLOG)
    #define CURRENT_LABEL "casper/syslog"
    #define TEST_TYPE "syslog"
#elif defined(MAC_FILEARGS)
    #define CURRENT_LABEL "casper/fileargs"
    #define TEST_TYPE "fileargs"
#else
    #define CURRENT_LABEL ""
    #define TEST_TYPE "baseline"
#endif

double get_elapsed_ns(struct timespec start, struct timespec end) {
    return (double)(end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
}

int main() {
    struct timespec start, end;
    int i;
    mac_t label;

    int mib[2];
    size_t len;
    char value[128];

    mib[0] = CTL_KERN;
    mib[1] = KERN_OSTYPE;

    if (strlen(CURRENT_LABEL) > 0) {
        if (mac_from_text(&label, CURRENT_LABEL) == -1) {
            fprintf(stderr, "Error parsing label %s: %s\n", CURRENT_LABEL, strerror(errno));
            exit(1);
        }
        if (mac_set_proc(label) == -1) {
            fprintf(stderr, "Error setting label: %s\n", strerror(errno));
            mac_free(label);
            exit(1);
        }
        mac_free(label);
    }

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (i = 0; i < ITERATIONS; i++) {
        len = sizeof(value);
        if (sysctl(mib, 2, value, &len, NULL, 0) == -1) {
			/* Do nothing */
		}
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    double total_ns = get_elapsed_ns(start, end);
    printf("%-10s | Total: %.4f s | Avg: %.2f ns\n",
           TEST_TYPE, total_ns / 1e9, total_ns / ITERATIONS);

    return 0;
}

