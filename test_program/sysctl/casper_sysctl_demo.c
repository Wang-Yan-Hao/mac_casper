#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include <capsicum_helpers.h>
#include <libcasper.h>
#include <casper/cap_sysctl.h>

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

	size = sizeof(value);
	if (cap_sysctlbyname(capsysctl, name, &value, &size, NULL, 0) < 0)
		err(1, "cap_sysctlbyname failed");

	printf("cap_sysctlbyname: %s = %d\n", name, value);

	if (cap_sysctlnametomib(capsysctl, name, mib, &miblen) < 0)
		err(1, "cap_sysctlnametomib failed");

	printf("cap_sysctlnametomib: %s ->", name);
	for (size_t i = 0; i < miblen; i++)
		printf(" %d", mib[i]);
	printf("\n");

	bool value2 = false;
	size = sizeof(value2);
	if (cap_sysctl(capsysctl, mib, miblen, &value2, &size, NULL, 0) < 0)
		err(1, "cap_sysctl failed");

	printf("cap_sysctl (via MIB): %s = %d\n", name, value2);

	cap_close(capsysctl);
	return 0;
}
