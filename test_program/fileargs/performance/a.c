#define _GNU_SOURCE
#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <limits.h>
#include <capsicum_helpers.h>
#include <libcasper.h>
#include <casper/cap_fileargs.h>

#define ITERATIONS 10000

static double time_diff(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

int main(int argc, char *argv[]) {
    int ch, i;
    cap_rights_t rights;
    fileargs_t *fa;
    struct stat sb;
    char resolved[PATH_MAX];
    FILE *fp;

    // Parse options
    while ((ch = getopt(argc, argv, "h")) != -1) {
        switch (ch) {
            case 'h':
            default:
                fprintf(stderr, "Usage: %s [files...]\n", argv[0]);
                return 1;
        }
    }

    argc -= optind;
    argv += optind;
    if (argc == 0)
        errx(1, "No files provided");

    cap_rights_init(&rights, CAP_READ, CAP_FSTAT, CAP_LOOKUP);
    fa = fileargs_init(argc, argv, O_RDONLY, 0, &rights,
                       FA_OPEN | FA_LSTAT | FA_REALPATH);
    if (fa == NULL)
        err(1, "fileargs_init failed");

    if (cap_enter() < 0 && errno != ENOSYS)
        err(1, "cap_enter failed");

    struct timespec start, end;
    double elapsed;

    // fileargs_open
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int j = 0; j < ITERATIONS; j++) {
        for (i = 0; i < argc; i++) {
            int fd = fileargs_open(fa, argv[i]);
            if (fd >= 0) close(fd);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("fileargs_open took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // fileargs_lstat
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int j = 0; j < ITERATIONS; j++) {
        for (i = 0; i < argc; i++) {
            fileargs_lstat(fa, argv[i], &sb);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("fileargs_lstat took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // fileargs_realpath
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int j = 0; j < ITERATIONS; j++) {
        for (i = 0; i < argc; i++) {
            fileargs_realpath(fa, argv[i], resolved);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("fileargs_realpath took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    // fileargs_fopen
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int j = 0; j < ITERATIONS; j++) {
        for (i = 0; i < argc; i++) {
            fp = fileargs_fopen(fa, argv[i], "r");
            if (fp) fclose(fp);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = time_diff(start, end);
    printf("fileargs_fopen took %f seconds for %d iterations\n", elapsed, ITERATIONS);

    fileargs_free(fa);
    return 0;
}

