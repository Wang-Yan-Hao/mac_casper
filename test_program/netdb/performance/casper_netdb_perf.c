#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <libcasper.h>
#include <casper/cap_netdb.h>
#include <capsicum_helpers.h>
#include <time.h>

#if defined(__aarch64__)
	#define ITERATIONS 10000
#elif defined(__amd64__)
	#define ITERATIONS 100000
#else
	#define ITERATIONS 1
#endif

static double time_diff(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

int main(void) {
    cap_channel_t *capcas, *capnetdb;
    struct protoent *proto;

    capcas = cap_init();
    if (capcas == NULL)
        err(1, "Unable to contact Casper");

    if (caph_enter_casper() < 0 && errno != ENOSYS)
        err(1, "Unable to enter capability mode");

    capnetdb = cap_service_open(capcas, "system.netdb");
    if (capnetdb == NULL)
        err(1, "Unable to open system.netdb service");

    cap_close(capcas);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; ++i) {
        proto = cap_getprotobyname(capnetdb, "tcp");
        if (proto == NULL)
            errx(1, "cap_getprotobyname failed");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = time_diff(start, end);
    printf("cap_getprotobyname took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    cap_close(capnetdb);
    return 0;
}
