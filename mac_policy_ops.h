#ifndef CASPER_MAC_H
#define CASPER_MAC_H

#define SLOT(l)		 ((struct mac_casper *)mac_label_get((l), casper_slot))
#define SLOT_SET(l, val) (mac_label_set((l), casper_slot, (uintptr_t)(val)))

static const char *MAC_CASPER_LABEL_NAME = "casper"; /* Module label */

/* Label type */
enum casper_label_type {
	CASPER_NONE = 0, /* Not Label */
	CASPER_DNS,
	CASPER_FILEARGS,
	CASPER_GRP,
	CASPER_NETDB,
	CASPER_PWD,
	CASPER_SYSCTL,
	CASPER_SYSLOG,
	CASPER_TYPE_LEN,
};

/* Label structure */
struct mac_casper {
	enum casper_label_type type;
};

static const char *casper_blocked_labels[] = {
	/* List of blocked labels */
	"dns", "fileargs", "grp", "netdb", "pwd", "sysctl", "syslog", NULL
};

/* Label string map */
struct casper_label_mapping {
	const char *name;
	enum casper_label_type type;
};

static const struct casper_label_mapping casper_label_map[] = {
	{ "dns", CASPER_DNS }, { "fileargs", CASPER_FILEARGS },
	{ "grp", CASPER_GRP }, { "netdb", CASPER_NETDB }, { "pwd", CASPER_PWD },
	{ "sysctl", CASPER_SYSCTL }, { "syslog", CASPER_SYSLOG },
	{ NULL, CASPER_NONE }
};

#endif // CASPER_MAC_H
