#ifndef CASPER_CHECKER_H
#define CASPER_CHECKER_H

/* DNS checker */
#define BUF_SIZE 1024 // Read in chunks
#define MAXNS	 3    // Limit how many nameservers we parse

int casper_check_dst_ip(const int type, struct sockaddr *sa);

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
	"/etc/nsswitch.conf", "/etc/pwd.db", "/etc/spwd.db",
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

#endif // CASPER_CHECKER_H
