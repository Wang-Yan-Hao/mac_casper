#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>

int main() {
    struct passwd *pwd;
    struct passwd pwd_buf;
    char buffer[1024];
    struct passwd *result;
    uid_t uid = getuid(); // Current user's UID
    const char *username = getlogin();

    // Get user information by UID
    pwd = getpwuid(uid);
    if (pwd) {
        printf("User (UID: %d): %s, Home: %s\n", pwd->pw_uid, pwd->pw_name, pwd->pw_dir);
    } else {
        perror("getpwuid failed");
    }

    // Get user information by username
    pwd = getpwnam(username);
    if (pwd) {
        printf("User (Name: %s): UID %d, Home: %s\n", pwd->pw_name, pwd->pw_uid, pwd->pw_dir);
    } else {
        perror("getpwnam failed");
    }

    // Reentrant version: getpwuid_r
    if (getpwuid_r(uid, &pwd_buf, buffer, sizeof(buffer), &result) == 0 && result) {
        printf("[Reentrant] User (UID: %d): %s, Home: %s\n", pwd_buf.pw_uid, pwd_buf.pw_name, pwd_buf.pw_dir);
    } else {
        perror("getpwuid_r failed");
    }

    // Iterate over all users with getpwent
    setpwent();
    while ((pwd = getpwent()) != NULL) {
        printf("User: %s (UID: %d)\n", pwd->pw_name, pwd->pw_uid);
    }
    endpwent();

    return 0;
}
