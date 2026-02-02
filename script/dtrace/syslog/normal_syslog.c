#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>

void log_message(int priority, const char *format, ...) {
    va_list args;
    va_start(args, format);
    vsyslog(priority, format, args);
    va_end(args);
}

int main(void) {
    // Open the system log
    openlog("SyslogExample", LOG_PID | LOG_CONS, LOG_USER);

    // Set log mask to only allow warnings and higher
    setlogmask(LOG_UPTO(LOG_WARNING));

    // Log messages with different priorities
    syslog(LOG_NOTICE, "This is a NOTICE message.");
    syslog(LOG_WARNING, "This is a WARNING message.");
    syslog(LOG_ERR, "This is an ERROR message.");

    // This debug message will be ignored because of the log mask
    syslog(LOG_DEBUG, "This DEBUG message will not be logged.");

    // Log using the custom function with vsyslog()
    log_message(LOG_ERR, "Logging using vsyslog: %s", "An error occurred!");

    // Close the log
    closelog();

    return 0;
}
