#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <grp.h>
#include <sys/types.h>
#include <sys/nv.h>
#include <libcasper.h>
#include <casper/cap_grp.h>

#define BUFFER_SIZE 1024

int main(void) {
    cap_channel_t *capcas, *capgrp;
    struct group *grp;
    struct group grp_buf;
    char buffer[BUFFER_SIZE];
    struct group *result;
    const char *cmds[] = { "getgrent", "getgrnam", "getgrgid", "setgroupent", "setgrent", "endgrent" };
    const char *fields[] = { "gr_name", "gr_gid", "gr_mem" };
    const char *names[] = { "wheel", "operator" };
    gid_t gids[] = { 0, 5 };  // Typically root and operator groups

    // Open Casper capability
    capcas = cap_init();
    if (capcas == NULL) {
        perror("cap_init");
        return 1;
    }

    // Enter capability mode
    // if (cap_enter() < 0 && errno != ENOSYS) {
    //     perror("cap_enter");
    //     return 1;
    // }

    // Open the system.grp service
    capgrp = cap_service_open(capcas, "system.grp");
    if (capgrp == NULL) {
        perror("cap_service_open");
        return 1;
    }
    cap_close(capcas);

    // Limit the commands
    if (cap_grp_limit_cmds(capgrp, cmds, sizeof(cmds) / sizeof(cmds[0])) != 0) {
        perror("cap_grp_limit_cmds");
        return 1;
    }

    // Limit the fields
    if (cap_grp_limit_fields(capgrp, fields, sizeof(fields) / sizeof(fields[0])) != 0) {
        perror("cap_grp_limit_fields");
        return 1;
    }

    // Limit the groups
    // if (cap_grp_limit_groups(capgrp, names, sizeof(names) / sizeof(names[0]), gids, sizeof(gids) / sizeof(gids[0])) != 0) {
    //     perror("cap_grp_limit_groups");
    //     return 1;
    // }

    // Iterate through group entries
    printf("Iterating through groups:\n");
    cap_setgrent(capgrp);
    while ((grp = cap_getgrent(capgrp)) != NULL) {
        printf("Group: %s (GID: %d)\n", grp->gr_name, grp->gr_gid);
    }
    cap_endgrent(capgrp);

    // Get group by name
    grp = cap_getgrnam(capgrp, "wheel");
    if (grp) {
        printf("Group 'wheel': GID = %d\n", grp->gr_gid);
    } else {
        perror("cap_getgrnam");
    }

    // Get group by GID
    grp = cap_getgrgid(capgrp, 0);
    if (grp) {
        printf("GID 0 corresponds to group: %s\n", grp->gr_name);
    } else {
        perror("cap_getgrgid");
    }

    // Reentrant versions
    printf("Using reentrant functions:\n");

    if (cap_getgrent_r(capgrp, &grp_buf, buffer, BUFFER_SIZE, &result) == 0 && result) {
        printf("cap_getgrent_r: Group: %s (GID: %d)\n", result->gr_name, result->gr_gid);
    }

    if (cap_getgrnam_r(capgrp, "wheel", &grp_buf, buffer, BUFFER_SIZE, &result) == 0 && result) {
        printf("cap_getgrnam_r: Group: %s (GID: %d)\n", result->gr_name, result->gr_gid);
    }

    if (cap_getgrgid_r(capgrp, 0, &grp_buf, buffer, BUFFER_SIZE, &result) == 0 && result) {
        printf("cap_getgrgid_r: GID 0 corresponds to group: %s\n", result->gr_name);
    }

    // Reset and iterate again
    cap_setgrent(capgrp);
    cap_setgroupent(capgrp, 1);
    printf("Iterating through groups again after reset:\n");
    while ((grp = cap_getgrent(capgrp)) != NULL) {
        printf("Group: %s (GID: %d)\n", grp->gr_name, grp->gr_gid);
    }
    cap_endgrent(capgrp);

    // Close capability
    cap_close(capgrp);

    return 0;
}
