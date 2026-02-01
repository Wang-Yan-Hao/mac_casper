#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mac.h>
#include <sys/nv.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <libcasper.h>
#include <casper/cap_dns.h>

static int
cap_dns_attack(cap_channel_t *chan, const char *cmd)
{
    nvlist_t *nvl;
    int error;

    /* Construct request */
    nvl = nvlist_create(0);
    if (nvl == NULL)
        return (ENOMEM);

    nvlist_add_string(nvl, "cmd", cmd);

    /* Send request to Casper service */
    nvl = cap_xfer_nvlist(chan, nvl);
    if (nvl == NULL) {
        printf("cap_xfer_nvlist failed\n");
        return (EAI_MEMORY);
    }

    printf("request sent successfully\n");

    /* Retrieve result */
    error = (int)nvlist_get_number(nvl, "error");
    printf("service returned error: %d\n", error);

    nvlist_destroy(nvl);
    return (error);
}

int
main(void)
{
    cap_channel_t *cap_casper;
    cap_channel_t *cap_net;
    int error;

    cap_casper = cap_init();
    if (cap_casper == NULL) {
        perror("cap_init");
        return (1);
    }

    cap_net = cap_service_open(cap_casper, "system.dns");
    if (cap_net == NULL) {
        perror("cap_service_open(system.dns)");
        return (1);
    }

    /* Simulate attack */
    error = cap_dns_attack(cap_net, "attack_exec");

    printf("attack result: %d\n", error);
    printf("main end\n");

    return (0);
}
