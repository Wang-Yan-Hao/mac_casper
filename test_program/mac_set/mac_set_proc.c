#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mac.h>
#include <errno.h>

int set_casper_label(const char *label_string) {
    mac_t label;
    int error;

    // 1. Convert the text string "casper/dns" into a mac_t structure
    // This prepares the label in memory but does not set it yet.
    error = mac_from_text(&label, label_string);
    if (error != 0) {
        perror("mac_from_text failed");
        return -1;
    }

    // 2. Apply the label to the current process
    // This triggers the system call that invokes the kernel hooks.
    error = mac_set_proc(label);
    if (error != 0) {
        perror("mac_set_proc failed");
        mac_free(label);
        return -1;
    }

    // 3. Free the memory allocated for the label
    mac_free(label);

    printf("Successfully set process label to: %s\n", label_string);
    return 0;
}

int main() {
    // Usage example
    if (set_casper_label("casper/dns") != 0) {
        fprintf(stderr, "Failed to set label.\n");
    }
    return 0;
}
