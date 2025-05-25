#ifndef CASPER_MAC_H
#define CASPER_MAC_H

#define BUF_SIZE	 512 // Read in chunks
#define MAX_NAMESERVERS	 10  // Limit how many nameservers we parse

#define SLOT(l)		 ((struct mac_casper *)mac_label_get((l), casper_slot))
#define SLOT_SET(l, val) (mac_label_set((l), casper_slot, (uintptr_t)(val)))

static const char *MAC_CASPER_LABEL_NAME = "casper"; /* Module label */

/* My label structure */
struct mac_casper {
	char label[20];
	char original_filename[40];
};

static const char *casper_blocked_labels[] = {
	/* List of blocked labels */
	"dns",
    "fileargs",
	// Add more labels here in the future
	NULL
};

/* DNS */
static const char *casper_dns_allowed_files_open[] = {
	"/etc/nsswitch.conf", "/etc/hosts", "/etc/resolv.conf", "/etc/services",
	NULL // Sentinel
};

#endif // CASPER_MAC_H
