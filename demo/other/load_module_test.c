#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>

int is_module_loaded(const char *name) {
    int modid = modfind(name);
    if (modid >= 0) {
        return 1; // found
    } else {
        return 0; // not found
    }
}

int main() {
    if (is_module_loaded("CaspeMAC")) {
        printf("CaspeMAC kernel module is loaded.\n");
    } else {
        printf("CaspeMAC kernel module is NOT loaded.\n");
    }
    return 0;
}
