#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/sysctl.h>

int main(void) {
    const char *name = "kern.trap_enotcap"; // Example sysctl variable
    int mib[CTL_MAXNAME];
    size_t miblen = CTL_MAXNAME;
    bool value;
    size_t size = sizeof(value);

    // Fetch value using sysctlbyname()
    if (sysctlbyname(name, &value, &size, NULL, 0) < 0) {
        perror("sysctlbyname");
        return 1;
    }
    printf("The value of %s is %d.\n", name, value);

    // Convert sysctl name to MIB using sysctlnametomib()
    if (sysctlnametomib(name, mib, &miblen) < 0) {
        perror("sysctlnametomib");
        return 1;
    }

    // Fetch value using sysctl() with MIB representation
    if (sysctl(mib, miblen, &value, &size, NULL, 0) < 0) {
        perror("sysctl");
        return 1;
    }
    printf("Retrieved via MIB: The value of %s is %d.\n", name, value);

    return 0;
}
