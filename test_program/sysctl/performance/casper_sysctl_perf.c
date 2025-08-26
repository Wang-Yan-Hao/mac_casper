#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <time.h>

#include <capsicum_helpers.h>
#include <libcasper.h>
#include <casper/cap_sysctl.h>

#if defined(__aarch64__)
	#define ITERATIONS 15000
#elif defined(__amd64__)
	#define ITERATIONS 100000
#else
	#define ITERATIONS 1
#endif

static double time_diff(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

int main(void) {
    cap_channel_t *capcas, *capsysctl;
    const char *name = "kern.trap_enotcap";
    int mib[CTL_MAXNAME];
    size_t miblen = CTL_MAXNAME;
    size_t size;
    bool value;

    capcas = cap_init();
    if (capcas == NULL)
        err(1, "Unable to contact Casper");

    if (caph_enter_casper() < 0 && errno != ENOSYS)
        err(1, "Unable to enter capability mode");

    capsysctl = cap_service_open(capcas, "system.sysctl");
    if (capsysctl == NULL)
        err(1, "Unable to open system.sysctl service");

    cap_close(capcas);

    cap_sysctl_limit_t *limit = cap_sysctl_limit_init(capsysctl);
    if (limit == NULL)
        err(1, "Failed to init sysctl limit");

    if (cap_sysctl_limit_name(limit, name, CAP_SYSCTL_READ) == NULL)
        err(1, "Failed to limit by name");

    if (cap_sysctl_limit(limit) < 0)
        err(1, "Failed to apply limit");

    struct timespec start, end;
    double elapsed;

    // cap_sysctlbyname
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        size = sizeof(value);
        if (cap_sysctlbyname(capsysctl, name, &value, &size, NULL, 0) < 0)
            err(1, "cap_sysctlbyname failed");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("cap_sysctlbyname took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // cap_sysctlnametomib
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        miblen = CTL_MAXNAME;
        if (cap_sysctlnametomib(capsysctl, name, mib, &miblen) < 0)
            err(1, "cap_sysctlnametomib failed");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("cap_sysctlnametomib took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // cap_sysctl
    cap_sysctlnametomib(capsysctl, name, mib, &miblen);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        size = sizeof(value);
        if (cap_sysctl(capsysctl, mib, miblen, &value, &size, NULL, 0) < 0)
            err(1, "cap_sysctl failed");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("cap_sysctl took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    cap_close(capsysctl);
    return 0;
}
