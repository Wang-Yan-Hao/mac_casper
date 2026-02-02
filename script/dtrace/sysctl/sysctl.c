#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/sysctl.h>
#include <libcasper.h>
#include <casper/cap_sysctl.h>

int main(void) {
    cap_channel_t *capcas, *capsysctl;
    const char *name = "kern.trap_enotcap"; // Example sysctl variable
    int mib[CTL_MAXNAME];
    size_t miblen = CTL_MAXNAME;
    bool value;
    size_t size = sizeof(value);

    // Open capability to Casper
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

    // Open system.sysctl service
    capsysctl = cap_service_open(capcas, "system.sysctl");
    if (capsysctl == NULL) {
        perror("cap_service_open");
        return 1;
    }
    cap_close(capcas); // No longer need Casper capability

    // Create a limit for accessing the specified sysctl variable
    cap_sysctl_limit_t *limit = cap_sysctl_limit_init(capsysctl);
    if (limit == NULL) {
        perror("cap_sysctl_limit_init");
        return 1;
    }

    // Restrict access to the named sysctl with read-only permissions
    if (cap_sysctl_limit_name(limit, name, CAP_SYSCTL_READ) == NULL) {
        perror("cap_sysctl_limit_name");
        return 1;
    }

    // Apply the sysctl limit
    if (cap_sysctl_limit(limit) < 0) {
        perror("cap_sysctl_limit");
        return 1;
    }

    // Fetch value using cap_sysctlbyname()
    if (cap_sysctlbyname(capsysctl, name, &value, &size, NULL, 0) < 0) {
        perror("cap_sysctlbyname");
        return 1;
    }
    printf("The value of %s is %d.\n", name, value);

    // Convert sysctl name to MIB using cap_sysctlnametomib()
    if (cap_sysctlnametomib(capsysctl, name, mib, &miblen) < 0) {
        perror("cap_sysctlnametomib");
        return 1;
    }

    // Fetch value using cap_sysctl() with MIB representation
    if (cap_sysctl(capsysctl, mib, miblen, &value, &size, NULL, 0) < 0) {
        perror("cap_sysctl");
        return 1;
    }
    printf("Retrieved via MIB: The value of %s is %d.\n", name, value);

    // Cleanup
    cap_close(capsysctl);

    return 0;
}
