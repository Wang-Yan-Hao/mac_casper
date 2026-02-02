#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <libcasper.h>
#include <casper/cap_pwd.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>

int main() {
    cap_channel_t *capcas, *cappwd;
    struct passwd *pwd;
    struct passwd pwd_buf;
    char buffer[1024];
    struct passwd *result;
    uid_t uid = getuid(); // Current user's UID
    const char *username = getlogin();

    // Open capability to Casper
    capcas = cap_init();
    if (capcas == NULL)
        err(1, "Unable to contact Casper");

    // Enter capability mode sandbox
    // if (cap_enter() < 0 && errno != ENOSYS)
    //     err(1, "Unable to enter capability mode");

    // Open `system.pwd` service
    cappwd = cap_service_open(capcas, "system.pwd");
    if (cappwd == NULL)
        err(1, "Unable to open system.pwd service");

    // Close Casper capability, we don't need it anymore
    cap_close(capcas);

    // Limit service to specific functions
    const char *cmds[] = {"getpwuid", "getpwnam", "getpwent"};
    if (cap_pwd_limit_cmds(cappwd, cmds, 3))
        err(1, "Unable to limit access to system.pwd service");

    // Limit service to specific fields
    const char *fields[] = {"pw_name", "pw_uid", "pw_dir"};
    if (cap_pwd_limit_fields(cappwd, fields, 3))
        err(1, "Unable to limit access to system.pwd service");

    // Limit service to specific users
    uid_t allowed_uids[] = {uid};  // Only allow access to the current user
    if (cap_pwd_limit_users(cappwd, NULL, 0, allowed_uids, 1))
        err(1, "Unable to limit access to system.pwd service");

    // Get user information by UID
    pwd = cap_getpwuid(cappwd, uid);
    if (pwd) {
        printf("User (UID: %d): %s, Home: %s\n", pwd->pw_uid, pwd->pw_name, pwd->pw_dir);
    } else {
        warn("cap_getpwuid failed");
    }

    // Get user information by username
    pwd = cap_getpwnam(cappwd, username);
    if (pwd) {
        printf("User (Name: %s): UID %d, Home: %s\n", pwd->pw_name, pwd->pw_uid, pwd->pw_dir);
    } else {
        warn("cap_getpwnam failed");
    }

    // Reentrant version: cap_getpwuid_r
    if (cap_getpwuid_r(cappwd, uid, &pwd_buf, buffer, sizeof(buffer), &result) == 0 && result) {
        printf("[Reentrant] User (UID: %d): %s, Home: %s\n", pwd_buf.pw_uid, pwd_buf.pw_name, pwd_buf.pw_dir);
    } else {
        warn("cap_getpwuid_r failed");
    }

    // Iterate over all users with cap_getpwent
    cap_setpwent(cappwd);
    while ((pwd = cap_getpwent(cappwd)) != NULL) {
        printf("User: %s (UID: %d)\n", pwd->pw_name, pwd->pw_uid);
    }
    cap_endpwent(cappwd);

    // Close the capability
    cap_close(cappwd);

    return 0;
}
