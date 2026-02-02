#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>

int main() {
    struct protoent *proto;

    // Get protocol information for TCP
    proto = getprotobyname("tcp");
    if (proto == NULL) {
        perror("getprotobyname");
        return EXIT_FAILURE;
    }
    printf("Protocol name: %s, Protocol number: %d\n", proto->p_name, proto->p_proto);

    // Get protocol information for UDP
    proto = getprotobyname("udp");
    if (proto == NULL) {
        perror("getprotobyname");
        return EXIT_FAILURE;
    }
    printf("Protocol name: %s, Protocol number: %d\n", proto->p_name, proto->p_proto);

    return EXIT_SUCCESS;
}
