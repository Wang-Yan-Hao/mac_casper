#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <time.h>

#include <capsicum_helpers.h>
#include <libcasper.h>
#include <casper/cap_syslog.h>

#if defined(__aarch64__)
	#define ITERATIONS 10000
#elif defined(__amd64__)
	#define ITERATIONS 100000
#else
	#define ITERATIONS 1
#endif

static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(void) {
    cap_channel_t *capcas, *capsyslog;

    capcas = cap_init();
    if (capcas == NULL)
        err(1, "Unable to contact Casper");

    if (caph_enter_casper() < 0 && errno != ENOSYS)
        err(1, "Unable to enter capability mode");

    capsyslog = cap_service_open(capcas, "system.syslog");
    if (capsyslog == NULL)
        err(1, "Unable to open system.syslog service");

    cap_close(capcas);

    cap_openlog(capsyslog, "cap_syslog_test", LOG_CONS | LOG_PID, LOG_USER);

    double start = get_time_sec();
    for (int i = 0; i < ITERATIONS; i++) {
        cap_syslog(capsyslog, LOG_INFO, "Syslog test message %d", i);
    }
    double end = get_time_sec();

    cap_closelog(capsyslog);
    cap_close(capsyslog);

    printf("cap_syslog took %.6f seconds for %d iterations\n", end - start, ITERATIONS);
    return 0;
}

