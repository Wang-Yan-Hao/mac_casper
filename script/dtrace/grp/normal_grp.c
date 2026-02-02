#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <grp.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

int main(void) {
    struct group *grp;
    struct group grp_buf;
    char buffer[BUFFER_SIZE];
    struct group *result;

    // Iterate through group entries
    printf("Iterating through groups:\n");
    setgrent(); // Rewind group database
    while ((grp = getgrent()) != NULL) {
        printf("Group: %s (GID: %d)\n", grp->gr_name, grp->gr_gid);
    }
    endgrent();

    // Get group by name
    grp = getgrnam("wheel");
    if (grp) {
        printf("Group 'wheel': GID = %d\n", grp->gr_gid);
    } else {
        perror("getgrnam");
    }

    // Get group by GID
    grp = getgrgid(0);
    if (grp) {
        printf("GID 0 corresponds to group: %s\n", grp->gr_name);
    } else {
        perror("getgrgid");
    }

    // Reentrant versions
    printf("Using reentrant functions:\n");

    if (getgrent_r(&grp_buf, buffer, BUFFER_SIZE, &result) == 0 && result) {
        printf("getgrent_r: Group: %s (GID: %d)\n", result->gr_name, result->gr_gid);
    }

    if (getgrnam_r("wheel", &grp_buf, buffer, BUFFER_SIZE, &result) == 0 && result) {
        printf("getgrnam_r: Group: %s (GID: %d)\n", result->gr_name, result->gr_gid);
    }

    if (getgrgid_r(0, &grp_buf, buffer, BUFFER_SIZE, &result) == 0 && result) {
        printf("getgrgid_r: GID 0 corresponds to group: %s\n", result->gr_name);
    }

    // Reset and iterate again
    setgrent();
    printf("Iterating through groups again after reset:\n");
    while ((grp = getgrent()) != NULL) {
        printf("Group: %s (GID: %d)\n", grp->gr_name, grp->gr_gid);
    }
    endgrent();

    return 0;
}
