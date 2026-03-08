#define WITH_CASPER

#include <sys/types.h>
#include <sys/nv.h>
#include <libcasper.h>
#include <casper/cap_grp.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
cap_attack(cap_channel_t *chan, const char *cmd)
{
    nvlist_t *nvlin, *nvlout;
    int attack_errno = -1;

    nvlin = nvlist_create(0);
    if (nvlin == NULL)
        return (ENOMEM);

    nvlist_add_string(nvlin, "cmd", cmd);

    nvlout = cap_xfer_nvlist(chan, nvlin);
    if (nvlout == NULL) {
        printf("cap_xfer_nvlist failed\n");
        return (EFAULT);
    }

    if (nvlist_exists_number(nvlout, "attack_errno"))
        attack_errno = (int)nvlist_get_number(nvlout, "attack_errno");
    else
        printf("Warning: 'attack_errno' not found in response.\n");

    nvlist_destroy(nvlout);

    return (attack_errno);
}

int
main(int argc, char *argv[])
{
    cap_channel_t *cap_casper, *cap_xxx;
    int attack_err;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ATTACK_TYPE>\n", argv[0]);
        fprintf(stderr, "Example: %s ATTACK_EXEC\n", argv[0]);
        fprintf(stderr, "Available: ATTACK_EXEC, ATTACK_FILE_READ, "
                        "ATTACK_FILE_WRITE, ATTACK_CRED, ATTACK_NET, "
                        "ATTACK_IPC, ATTACK_KLD, ATTACK_SYSCTL\n");
        return (1);
    }

    const char *attack_cmd = argv[1];

    cap_casper = cap_init();
    if (cap_casper == NULL) {
        perror("cap_init");
        return (1);
    }

    cap_xxx = cap_service_open(cap_casper, "system.grp");
    if (cap_xxx == NULL) {
        perror("cap_service_open() failed");
        cap_close(cap_casper);
        return (1);
    }

    printf("--- Effectiveness Evaluation ---\n");
    printf("Targeting service: system.grp\n");
    printf("Executing command: %s\n", attack_cmd);

    attack_err = cap_attack(cap_xxx, attack_cmd);

    printf("--------------------------------\n");
    if (attack_err == EACCES || attack_err == EPERM) {
        printf("[SUCCESS] MAC Policy blocked the attack! (errno = %d: %s)\n",
               attack_err, strerror(attack_err));
    } else if (attack_err == 0) {
        printf("[FAILED] Attack bypassed the policy! (Exited with 0)\n");
    } else if (attack_err == -1) {
         printf("[ERROR] Failed to get attack result from Casper.\n");
    } else {
        printf("[RESULT] Attack failed with unexpected errno = %d (%s)\n",
               attack_err, strerror(attack_err));
    }
    printf("--------------------------------\n");

    cap_close(cap_xxx);
    cap_close(cap_casper);
    return (0);
}
