#ifndef CASPER_MAC_H
#define CASPER_MAC_H

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
	"dns", "fileargs", "grp", "netdb", "pwd", "sysctl", "syslog",
	// Add more labels here in the future
	NULL
};

/* DNS */
static const char *casper_dns_allowed_files_open[] = {
	"/etc/nsswitch.conf", "/etc/hosts", "/etc/resolv.conf", "/etc/services",
	NULL // Sentinel
};

/* GRP */
static const char *grp_allowed_files_open[] = {
	"/etc/nsswitch.conf", "/etc/group", "/var/db/cache/group.cache",
	NULL // Sentinel
};

/* NETDB */
static const char *netdb_allowed_files_open[] = {
	"/etc/nsswitch.conf", "/etc/protocols",
	NULL // Sentinel
};

/* PWD */
static const char *pwd_allowed_files_open[] = {
	"/etc/nsswitch.conf", "/etc/spwd.db", "/etc/pwd.db",
	NULL // Sentinel
};

/* SYSCTL */
static const char *sysctl_allowed_files_open[] = {
	"/etc/pwd.db",
	NULL // Sentinel
};

/* SYSLOG */
static const char *syslog_allowed_files_open[] = {
	"/var/run/log", "/etc/localtime", "/etc/pwd.db",
	NULL // Sentinel
};

#endif // CASPER_MAC_H
