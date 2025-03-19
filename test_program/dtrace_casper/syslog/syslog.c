#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/nv.h>
#include <libcasper.h>
#include <casper/cap_syslog.h>

void log_message(cap_channel_t *capsyslog, int priority, const char *format, ...) {
    va_list args;
    va_start(args, format);
    cap_vsyslog(capsyslog, priority, format, args);
    va_end(args);
}

int main(void) {
    cap_channel_t *capcas, *capsyslog;

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

    // Open the system.syslog service
    capsyslog = cap_service_open(capcas, "system.syslog");
    if (capsyslog == NULL) {
        perror("cap_service_open");
        return 1;
    }
    cap_close(capcas); // No longer need Casper capability

    // Open the log
    cap_openlog(capsyslog, "CapSyslogExample", LOG_PID | LOG_CONS, LOG_USER);

    // Set log mask to only allow warnings and higher
    cap_setlogmask(capsyslog, LOG_UPTO(LOG_WARNING));

    // Log messages with different priorities
    cap_syslog(capsyslog, LOG_NOTICE, "This is a NOTICE message.");
    cap_syslog(capsyslog, LOG_WARNING, "This is a WARNING message.");
    cap_syslog(capsyslog, LOG_ERR, "This is an ERROR message.");

    // This debug message will be ignored because of the log mask
    cap_syslog(capsyslog, LOG_DEBUG, "This DEBUG message will not be logged.");

    // Log using the custom function with cap_vsyslog()
    log_message(capsyslog, LOG_ERR, "Logging using cap_vsyslog: %s", "An error occurred!");

    // Close the log
    cap_closelog(capsyslog);

    // Close capability
    cap_close(capsyslog);

    return 0;
}
