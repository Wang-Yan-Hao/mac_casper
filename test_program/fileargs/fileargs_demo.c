#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <capsicum_helpers.h>
#include <libcasper.h>
#include <casper/cap_fileargs.h>

#include <string.h>
#include <sys/mac.h>


int main(int argc, char *argv[]) {
    int ch, fd, i;
    cap_rights_t rights;
    fileargs_t *fa;
    struct stat sb;
    char resolved[PATH_MAX];
    FILE *fp;

    // Parse options (e.g., -h)
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

    if (argc == 0) {
        errx(1, "No files provided");
    }

    // Create rights
    cap_rights_init(&rights, CAP_READ, CAP_SEEK, CAP_FSTAT, CAP_LOOKUP, CAP_FCNTL);

    // 1. fileargs_init
    fa = fileargs_init(argc, argv, O_RDONLY, 0, &rights,
                   FA_OPEN | FA_LSTAT | FA_REALPATH);
    if (fa == NULL) {
        err(1, "fileargs_init failed");
    } else {
        printf("fileargs_init: success\n");
    }

    // Enter capability mode
    if (caph_enter_casper() < 0 && errno != ENOSYS) {
        err(1, "cap_enter failed");
    }

    // Loop over each file
    for (i = 0; i < argc; i++) {
        const char *filename = argv[i];

        // 2. fileargs_open
        fd = fileargs_open(fa, filename);
        if (fd < 0) {
            warn("fileargs_open failed: %s", filename);
        } else {
            printf("fileargs_open: opened %s (fd = %d)\n", filename, fd);
            close(fd);
        }

        // 3. fileargs_lstat
        if (fileargs_lstat(fa, filename, &sb) == 0) {
            printf("fileargs_lstat: Size of %s: %lld bytes\n", filename, (long long)sb.st_size);
        } else {
            warn("fileargs_lstat failed: %s", filename);
        }

        // 4. fileargs_realpath
        if (fileargs_realpath(fa, filename, resolved) != NULL) {
            printf("fileargs_realpath: Real path: %s\n", resolved);
        } else {
            warn("fileargs_realpath failed: %s", filename);
        }

        // 5. fileargs_fopen
        fp = fileargs_fopen(fa, filename, "r");
        if (fp != NULL) {
            printf("fileargs_fopen: fopen succeeded for %s\n", filename);
            fclose(fp);
        } else {
            warn("fileargs_fopen failed: %s", filename);
        }
    }

    // 6. fileargs_free
    fileargs_free(fa);

    return 0;
}

