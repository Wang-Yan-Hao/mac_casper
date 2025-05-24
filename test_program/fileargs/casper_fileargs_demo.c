#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mac.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>

int main() {
    mac_t mac_label;
    const char *label = "casper/fileargs";

    // Convert the text label to the internal mac_t format
    if (mac_from_text(&mac_label, label) != 0) {
        printf("Failed to convert label from text\n");
        return -1;
    }

    int ret = 0;
    // Apply the label to the current process
    if ((ret = mac_set_proc(mac_label)) != 0) {
        printf("Error: %s\n", strerror(errno));
        printf("Failed to set MAC label on process\n");
        mac_free(mac_label);
        return -1;
    }

    mac_free(mac_label);

    int fd = open("test.txt", O_RDONLY);
    if (fd == -1) {
        printf("Open failed\n");
    } else {
        printf("Open success\n");
    }

    /* Test open other file will failed */
    if (chdir("/") == -1) {
        printf("Chdir failed\n");
    } else {
        printf("Chdir success\n");
    }

    return 0;
}
