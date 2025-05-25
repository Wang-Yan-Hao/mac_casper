#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <capsicum_helpers.h>
#include <libcasper.h>
#include <casper/cap_pwd.h>

int main() {
    cap_channel_t *capcas, *cappwd;
    struct passwd *pw;
    struct passwd pwbuf;
    char buffer[1024];
    struct passwd *result = NULL;
    const char *cmds[] = {
        "getpwent", "getpwnam", "getpwuid",
        "getpwent_r", "getpwnam_r", "getpwuid_r",
        "setpassent", "setpwent", "endpwent"
    };
    const char *fields[] = {
        "pw_name", "pw_passwd", "pw_uid", "pw_gid",
        "pw_change", "pw_class", "pw_gecos", "pw_dir",
        "pw_shell", "pw_expire"
    };
    const char *names[] = { "root" };
    uid_t uids[] = { 0 };

    capcas = cap_init();
    if (capcas == NULL)
        err(1, "Unable to contact Casper");

    if (caph_enter_casper() < 0 && errno != ENOSYS)
        err(1, "Unable to enter capability mode");

    cappwd = cap_service_open(capcas, "system.pwd");
    if (cappwd == NULL)
        err(1, "Unable to open system.pwd service");

    cap_close(capcas);

    if (cap_pwd_limit_cmds(cappwd, cmds, sizeof(cmds) / sizeof(cmds[0])) != 0)
        err(1, "Unable to limit commands");

    if (cap_pwd_limit_fields(cappwd, fields, sizeof(fields) / sizeof(fields[0])) != 0)
        err(1, "Unable to limit fields");

    if (cap_pwd_limit_users(cappwd, names, 1, uids, 1) != 0)
        err(1, "Unable to limit users");

    cap_setpassent(cappwd, 1);
    cap_setpwent(cappwd);

    pw = cap_getpwent(cappwd);
    if (pw != NULL)
        printf("cap_getpwent(): First user: %s\n", pw->pw_name);
    else
        perror("cap_getpwent failed");

    pw = cap_getpwnam(cappwd, "root");
    if (pw != NULL)
        printf("cap_getpwnam(): root has UID: %d\n", pw->pw_uid);
    else
        perror("cap_getpwnam failed");

    pw = cap_getpwuid(cappwd, 0);
    if (pw != NULL)
        printf("cap_getpwuid(): UID 0 is: %s\n", pw->pw_name);
    else
        perror("cap_getpwuid failed");

    if (cap_getpwent_r(cappwd, &pwbuf, buffer, sizeof(buffer), &result) == 0 && result != NULL)
        printf("cap_getpwent_r(): Reentrant user: %s\n", result->pw_name);
    else
        perror("cap_getpwent_r failed");

    if (cap_getpwnam_r(cappwd, "root", &pwbuf, buffer, sizeof(buffer), &result) == 0 && result != NULL)
        printf("cap_getpwnam_r(): root -> %s\n", result->pw_name);
    else
        perror("cap_getpwnam_r failed");

    if (cap_getpwuid_r(cappwd, 0, &pwbuf, buffer, sizeof(buffer), &result) == 0 && result != NULL)
        printf("cap_getpwuid_r(): UID 0 -> %s\n", result->pw_name);
    else
        perror("cap_getpwuid_r failed");

    cap_endpwent(cappwd);
    cap_close(cappwd);

    return 0;
}
