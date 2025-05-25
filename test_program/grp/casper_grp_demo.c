#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <grp.h>
#include <unistd.h>
#include <sys/nv.h>
#include <capsicum_helpers.h>
#include <libcasper.h>
#include <casper/cap_grp.h>
#include <sys/mac.h>

int main() {
    cap_channel_t *capcas, *capgrp;
    const char *cmds[] = {
        "getgrent", "getgrnam", "getgrgid",
        "getgrent_r", "getgrnam_r", "getgrgid_r",
        "setgroupent", "setgrent", "endgrent"
    };
    const char *fields[] = { "gr_name", "gr_passwd", "gr_gid", "gr_mem" };

    capcas = cap_init();
    if (capcas == NULL) {
        perror("cap_init");
        exit(1);
    }

    if (caph_enter_casper() < 0 && errno != ENOSYS) {
        perror("caph_enter_casper");
        exit(1);
    }

    capgrp = cap_service_open(capcas, "system.grp");
    if (capgrp == NULL) {
        perror("cap_service_open");
        exit(1);
    }

    cap_close(capcas);

    if (cap_grp_limit_cmds(capgrp, cmds, sizeof(cmds) / sizeof(cmds[0])) != 0) {
        perror("cap_grp_limit_cmds");
        exit(1);
    }

    if (cap_grp_limit_fields(capgrp, fields, sizeof(fields) / sizeof(fields[0])) != 0) {
        perror("cap_grp_limit_fields");
        exit(1);
    }

    const char *names[] = { "wheel" };
    if (cap_grp_limit_groups(capgrp, names, 1, NULL, 0) < 0) {
        perror("cap_grp_limit_groups (name)");
    }

    // === cap_setgroupent() ===
    // The function setgroupent() returns the value 1 if successful,
    // otherwise the  value  0  is  returned
    if (cap_setgroupent(capgrp, 1) == 1) {
        printf("cap_setgroupent(): Group database prepared\n");
    } else {
        perror("cap_setgroupent");
    }

    // === cap_getgrent() ===
    struct group *g = cap_getgrent(capgrp);
    if (g != NULL) {
        printf("cap_getgrent(): First group name: %s\n", g->gr_name);
    } else {
        perror("cap_getgrent");
    }

    // === cap_getgrnam() ===
    g = cap_getgrnam(capgrp, "wheel");
    if (g != NULL) {
        printf("cap_getgrnam(): Group 'wheel' has GID: %d\n", g->gr_gid);
    } else {
        perror("cap_getgrnam failed");
    }

    // === cap_getgrgid() ===
    g = cap_getgrgid(capgrp, 0);
    if (g != NULL) {
        printf("cap_getgrgid(): GID 0 is group: %s\n", g->gr_name);
    } else {
        perror("cap_getgrgid");
    }

    // === cap_setgrent() ===
    cap_setgrent(capgrp);

    // === cap_getgrent_r() ===
    struct group grp_buf;
    char buffer[1024];
    struct group *result = NULL;
    if (cap_getgrent_r(capgrp, &grp_buf, buffer, sizeof(buffer), &result) == 0 && result != NULL) {
        printf("cap_getgrent_r(): Reentrant getgrent: %s\n", result->gr_name);
    } else {
        perror("cap_getgrent_r failed");
    }

    // === cap_getgrnam_r() ===
    if (cap_getgrnam_r(capgrp, "wheel", &grp_buf, buffer, sizeof(buffer), &result) == 0 && result != NULL) {
        printf("cap_getgrnam_r(): Reentrant getgrnam: %s\n", result->gr_name);
    } else {
        perror("cap_getgrnam_r failed");
    }

    // === cap_getgrgid_r() ===
    if (cap_getgrgid_r(capgrp, 0, &grp_buf, buffer, sizeof(buffer), &result) == 0 && result != NULL) {
        printf("cap_getgrgid_r(): Reentrant getgrgid: %s\n", result->gr_name);
    } else {
        perror("cap_getgrgid_r failed");
    }

    // === cap_endgrent() ===
    cap_endgrent(capgrp);

    cap_close(capgrp);
    return 0;
}
