#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <err.h>
#include <unistd.h>
#include <syslog.h>
#include <capsicum_helpers.h>
#include <libcasper.h>
#include <casper/cap_syslog.h>

void log_with_vsyslog(cap_channel_t *chan, int priority, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	cap_vsyslog(chan, priority, fmt, ap);
	va_end(ap);
}

int main(void) {
	cap_channel_t *capcas, *capsyslog;

	capcas = cap_init();
	if (capcas == NULL)
		err(1, "Unable to contact Casper");

	if (caph_enter_casper() < 0 && errno != ENOSYS)
		err(1, "Unable to enter capability mode");

	capsyslog = cap_service_open(capcas, "system.syslog");
	if (capsyslog == NULL)
		err(1, "Unable to open system.syslog service");

	cap_close(capcas);

	// 5. Set log mask (only allow LOG_NOTICE and higher)
	int oldmask = cap_setlogmask(capsyslog, LOG_UPTO(LOG_NOTICE));
	printf("Old log mask was: 0x%x\n", oldmask);

	// 6. Open logging session
	cap_openlog(capsyslog, "cap_test", LOG_PID | LOG_CONS, LOG_USER);

	// 7. Log a message with cap_syslog()
	cap_syslog(capsyslog, LOG_NOTICE, "cap_syslog: Logging with LOG_NOTICE");

	// 8. Log using cap_vsyslog()
	log_with_vsyslog(capsyslog, LOG_ERR, "cap_vsyslog: Error level message: %s", "example");

	// 9. Close logging session
	cap_closelog(capsyslog);

	cap_close(capsyslog);

	return 0;
}
