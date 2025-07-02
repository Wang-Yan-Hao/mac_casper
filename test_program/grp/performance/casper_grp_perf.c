#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <capsicum_helpers.h>
#include <libcasper.h>
#include <casper/cap_grp.h>

#if defined(__aarch64__)
	#define ITERATIONS 10000
#elif defined(__amd64__)
	#define ITERATIONS 1000
#else
	#define ITERATIONS 1
#endif

#define BUF_SIZE 1024

static double time_diff(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

int main(void) {
    cap_channel_t *capcas, *capgrp;
    struct timespec start, end;
    double elapsed;
    struct group *g, *result;
    struct group grp_buf;
    char buffer[BUF_SIZE];

    const char *cmds[] = {
        "getgrent", "getgrnam", "getgrgid",
        "getgrent_r", "getgrnam_r", "getgrgid_r",
        "setgrent", "endgrent"
    };
    const char *fields[] = { "gr_name", "gr_passwd", "gr_gid", "gr_mem" };
    const char *groupname = "wheel";
    gid_t gid = 0;

    capcas = cap_init();
    if (capcas == NULL) err(1, "cap_init");

    if (caph_enter_casper() < 0 && errno != ENOSYS)
        err(1, "caph_enter_casper");

    capgrp = cap_service_open(capcas, "system.grp");
    if (capgrp == NULL) err(1, "cap_service_open");

    cap_close(capcas);

    if (cap_grp_limit_cmds(capgrp, cmds, sizeof(cmds) / sizeof(cmds[0])) != 0)
        err(1, "cap_grp_limit_cmds");

    if (cap_grp_limit_fields(capgrp, fields, sizeof(fields) / sizeof(fields[0])) != 0)
        err(1, "cap_grp_limit_fields");

    if (cap_grp_limit_groups(capgrp, &groupname, 1, NULL, 0) < 0)
        err(1, "cap_grp_limit_groups");

    // === cap_getgrnam ===
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        g = cap_getgrnam(capgrp, groupname);
        if (g == NULL) err(1, "cap_getgrnam");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("cap_getgrnam took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // === cap_getgrnam_r ===
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        if (cap_getgrnam_r(capgrp, groupname, &grp_buf, buffer, BUF_SIZE, &result) != 0 || result == NULL)
            err(1, "cap_getgrnam_r");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("cap_getgrnam_r took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // === cap_getgrgid ===
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        g = cap_getgrgid(capgrp, gid);
        if (g == NULL) err(1, "cap_getgrgid");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("cap_getgrgid took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // === cap_getgrgid_r ===
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        if (cap_getgrgid_r(capgrp, gid, &grp_buf, buffer, BUF_SIZE, &result) != 0 || result == NULL)
            err(1, "cap_getgrgid_r");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("cap_getgrgid_r took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // === cap_getgrent with cap_setgrent loop ===
    int count = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (count < ITERATIONS) {
        g = cap_getgrent(capgrp);
        if (g == NULL) {
            cap_setgrent(capgrp);
            continue;
        }
        count++;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("cap_getgrent took %f seconds for %d iterations (with reset)\n", elapsed, ITERATIONS);

    // === cap_getgrent_r with cap_setgrent loop ===
    count = 0;
    cap_setgrent(capgrp);
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (count < ITERATIONS) {
        if (cap_getgrent_r(capgrp, &grp_buf, buffer, BUF_SIZE, &result) != 0 || result == NULL) {
            cap_setgrent(capgrp);
            continue;
        }
        count++;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("cap_getgrent_r took %f seconds for %d iterations (with reset)\n", elapsed, ITERATIONS);

    cap_endgrent(capgrp);
    cap_close(capgrp);
    return 0;
}
