#define WITH_CASPER

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <libcasper.h>
#include <casper/cap_netdb.h>
#include <capsicum_helpers.h>

int main(void) {
    cap_channel_t *capcas, *capnetdb;
    struct protoent *proto;

    // Open capability to Casper
    capcas = cap_init();
    if (capcas == NULL)
        err(1, "Unable to contact Casper");

    // Enter capability mode
    if (caph_enter_casper() < 0 && errno != ENOSYS)
        err(1, "Unable to enter capability mode");

    // Open system.netdb service
    capnetdb = cap_service_open(capcas, "system.netdb");
    if (capnetdb == NULL)
        err(1, "Unable to open system.netdb service");

    // Close original Casper channel
    cap_close(capcas);

    // Use the service to get protocol by name
    proto = cap_getprotobyname(capnetdb, "tcp");
    if (proto == NULL)
        errx(1, "cap_getprotobyname failed");

    printf("Protocol: %s, Number: %d\n", proto->p_name, proto->p_proto);

    // Clean up
    cap_close(capnetdb);
    return 0;
}
