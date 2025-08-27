#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <capsicum_helpers.h>
#include <libcasper.h>
#include <casper/cap_pwd.h>

#if defined(__aarch64__)
	#define ITERATIONS 8000
#elif defined(__amd64__)
	#define ITERATIONS 40000
#else
	#define ITERATIONS 1
#endif

static double time_diff(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

int main() {
    cap_channel_t *capcas, *cappwd;
    struct passwd *pw;
    struct passwd pwbuf;
    char buffer[1024];
    struct passwd *result = NULL;
    const char *names[] = { "root" };
    uid_t uids[] = { 0 };

    capcas = cap_init();
    if (capcas == NULL) err(1, "cap_init failed");
    if (caph_enter_casper() < 0 && errno != ENOSYS) err(1, "caph_enter_casper failed");

    cappwd = cap_service_open(capcas, "system.pwd");
    if (cappwd == NULL) err(1, "cap_service_open failed");

    cap_close(capcas);

    const char *cmds[] = {
        "getpwent", "getpwnam", "getpwuid",
        "getpwent_r", "getpwnam_r", "getpwuid_r",
        "setpassent", "setpwent", "endpwent"
    };
    const char *fields[] = {
        "pw_name", "pw_passwd", "pw_uid", "pw_gid",
        "pw_change", "pw_class", "pw_gecos", "pw_dir",
        "pw_shell", "pw_expire"
    };

    if (cap_pwd_limit_cmds(cappwd, cmds, sizeof(cmds) / sizeof(cmds[0])) != 0)
        err(1, "cap_pwd_limit_cmds failed");
    if (cap_pwd_limit_fields(cappwd, fields, sizeof(fields) / sizeof(fields[0])) != 0)
        err(1, "cap_pwd_limit_fields failed");
    if (cap_pwd_limit_users(cappwd, names, 1, uids, 1) != 0)
        err(1, "cap_pwd_limit_users failed");

    struct timespec start, end;
    double elapsed;

    // cap_getpwnam
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        pw = cap_getpwnam(cappwd, "root");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("cap_getpwnam took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // cap_getpwnam_r
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        cap_getpwnam_r(cappwd, "root", &pwbuf, buffer, sizeof(buffer), &result);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("cap_getpwnam_r took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // cap_getpwuid
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        pw = cap_getpwuid(cappwd, 0);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("cap_getpwuid took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // cap_getpwuid_r
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        cap_getpwuid_r(cappwd, 0, &pwbuf, buffer, sizeof(buffer), &result);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("cap_getpwuid_r took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // cap_getpwent with reset
    cap_setpassent(cappwd, 1);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        cap_setpwent(cappwd);
        pw = cap_getpwent(cappwd);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("cap_getpwent took %f seconds for %d iterations (with reset)\n", elapsed, ITERATIONS);

    // cap_getpwent_r with reset
    cap_setpassent(cappwd, 1);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        cap_setpwent(cappwd);
        cap_getpwent_r(cappwd, &pwbuf, buffer, sizeof(buffer), &result);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("cap_getpwent_r took %f seconds for %d iterations (with reset)\n", elapsed, ITERATIONS);

    cap_endpwent(cappwd);
    cap_close(cappwd);
    return 0;
}
