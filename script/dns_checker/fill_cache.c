#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mac.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

/* Must match the definition in your Kernel Module */
#define CASPER_POLICY_NAME "CasperMAC"
#define CASPER_CMD_SET_DNS 1
#define CASPER_MAXNS       3

struct casper_dns_update_args {
    int count;
    struct sockaddr_storage ns[CASPER_MAXNS];
};

/* Helper to trim whitespace */
char *trim_whitespace(char *str) {
    char *end;

    // Trim leading space
    while(isspace((unsigned char)*str)) str++;

    if(*str == 0) return str;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;

    // Write new null terminator
    *(end+1) = 0;

    return str;
}

int main(int argc, char *argv[]) {
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    struct casper_dns_update_args args;
    int ret;

    /* Initialize the structure */
    memset(&args, 0, sizeof(args));
    args.count = 0;

    printf("Casper DNS Loader: Parsing /etc/resolv.conf...\n");

    fp = fopen("/etc/resolv.conf", "r");
    if (fp == NULL) {
        perror("Failed to open /etc/resolv.conf");
        return 1;
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        char *ptr = line;

        // Skip leading whitespace
        while (isspace((unsigned char)*ptr)) ptr++;

        // Skip comments (# or ;) and empty lines
        if (*ptr == '#' || *ptr == ';' || *ptr == '\0')
            continue;

        // Check for "nameserver" keyword
        if (strncmp(ptr, "nameserver", 10) == 0) {
            char *ip_str = ptr + 10;

            // Limit to MAXNS
            if (args.count >= CASPER_MAXNS) {
                printf("Warning: Reached MAXNS (%d), ignoring extra servers.\n", CASPER_MAXNS);
                break;
            }

            // Clean up the IP string (trim spaces and comments)
            ip_str = trim_whitespace(ip_str);

            // Remove inline comments if any (e.g. 8.8.8.8 # Google)
            char *comment = strpbrk(ip_str, "#;");
            if (comment) *comment = '\0';
            ip_str = trim_whitespace(ip_str);

            struct sockaddr_in *sin4 = (struct sockaddr_in *)&args.ns[args.count];
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&args.ns[args.count];

            // Try parsing as IPv4
            if (inet_pton(AF_INET, ip_str, &sin4->sin_addr) == 1) {
                sin4->sin_family = AF_INET;
                sin4->sin_len = sizeof(struct sockaddr_in);
                // sin4->sin_port = htons(53); // Optional: if you check port
                printf("  Found IPv4 Nameserver: %s\n", ip_str);
                args.count++;
            }
            // Try parsing as IPv6
            else if (inet_pton(AF_INET6, ip_str, &sin6->sin6_addr) == 1) {
                sin6->sin6_family = AF_INET6;
                sin6->sin6_len = sizeof(struct sockaddr_in6);
                // sin6->sin6_port = htons(53); // Optional
                printf("  Found IPv6 Nameserver: %s\n", ip_str);
                args.count++;
            } else {
                printf("  Warning: Invalid IP format in nameserver line: '%s'\n", ip_str);
            }
        }
    }

    fclose(fp);
    if (line) free(line);

    /* Send to Kernel via MAC Syscall */
    printf("Casper DNS Loader: Sending %d servers to kernel module '%s'...\n",
           args.count, CASPER_POLICY_NAME);

    ret = mac_syscall(CASPER_POLICY_NAME, CASPER_CMD_SET_DNS, &args);

    if (ret != 0) {
        perror("mac_syscall failed");
        if (errno == ENOSYS) {
            fprintf(stderr, "Error: MAC module '%s' is not loaded or does not implement syscall.\n", CASPER_POLICY_NAME);
        } else if (errno == EPERM) {
            fprintf(stderr, "Error: Permission denied (Are you root?)\n");
        }
        return 1;
    }

    printf("Casper DNS Loader: Success.\n");
    return 0;
}
