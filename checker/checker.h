#ifndef CASPER_CHECKER_H
#define CASPER_CHECKER_H

#include "../label.h"
#include "../mac_policy_ops.h"

/* DNS checker */
#define BUF_SIZE 1024 // Read in chunks
#define MAXNS	 3    // Limit how many nameservers we parse

int casper_check_dst_ip(const int type, struct sockaddr *sa);
int casper_check_allowed_open(struct mac_casper *subj, struct mac_casper *obj);

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
	"/var/run/log", "/dev/console", "/etc/localtime", "/etc/pwd.db",
	NULL // Sentinel
};

/* ==========================================================
 * Policy Map
 * ========================================================== */

struct cas_access_rule {
	enum cas_sub_label subj;
	const enum cas_obj_label
	    *allowed_list; /* Pointer to an external array */
};

static const enum cas_obj_label dns_allow[] = {
	OBJ_NSS_CONFIG, OBJ_NET_RESOLVE, OBJ_NET_SERVICES,
	OBJ_NONE /* Terminator */
};

static const enum cas_obj_label grp_allow[] = { OBJ_NSS_CONFIG, OBJ_GROUP_DB,
	OBJ_NONE };

static const enum cas_obj_label netdb_allow[] = { OBJ_NSS_CONFIG,
	OBJ_NET_SERVICES, OBJ_NET_PROTOCOLS, OBJ_NONE };

static const enum cas_obj_label pwd_allow[] = { OBJ_NSS_CONFIG, OBJ_PWD_PUBLIC,
	OBJ_PWD_SHADOW, OBJ_NONE };

static const enum cas_obj_label sysctl_allow[] = { OBJ_PWD_PUBLIC, OBJ_NONE };

static const enum cas_obj_label syslog_allow[] = { OBJ_PWD_PUBLIC, OBJ_SYS_TIME,
	OBJ_SYS_LOG, OBJ_NONE };

static const struct cas_access_rule casper_open_map[] = { { SUB_DNS,
							      dns_allow },
	{ SUB_GRP, grp_allow }, { SUB_NETDB, netdb_allow },
	{ SUB_PWD, pwd_allow }, { SUB_SYSCTL, sysctl_allow },
	{ SUB_SYSLOG, syslog_allow }, { SUB_NONE, NULL } };

#endif // CASPER_CHECKER_H
