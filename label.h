#ifndef CASPER_LABEL_H
#define CASPER_LABEL_H

/* ==========================================================
 * Subject (Process) Definitions
 * ========================================================== */

/* Subj label type */
enum cas_sub_label {
	SUB_NONE = 0, /* Not Label */
	SUB_DNS,
	SUB_FILEARGS,
	SUB_GRP,
	SUB_NETDB,
	SUB_PWD,
	SUB_SYSCTL,
	SUB_SYSLOG,
	SUB_LABEL_LEN, // Len
};

struct cas_sub_label_map {
	const char *name;
	enum cas_sub_label type;
};

static const struct cas_sub_label_map cas_sub_label_map[] = {
	{ "dns", SUB_DNS }, { "fileargs", SUB_FILEARGS }, { "grp", SUB_GRP },
	{ "netdb", SUB_NETDB }, { "pwd", SUB_PWD }, { "sysctl", SUB_SYSCTL },
	{ "syslog", SUB_SYSLOG }, { NULL, SUB_NONE } /* Sentinel */
};

/* ==========================================================
 * Object (File) Definitions
 * ========================================================== */

/* Obj label type */
enum cas_obj_label {
	OBJ_NONE = 0,
	OBJ_NSS_CONFIG,
	OBJ_NET_RESOLVE,
	OBJ_NET_SERVICES,
	OBJ_GROUP_DB,
	OBJ_NET_PROTOCOLS,
	OBJ_PWD_PUBLIC,
	OBJ_PWD_SHADOW,
	OBJ_SYS_TIME,
	OBJ_SYS_LOG,
	OBJ_LABEL_LEN // Len
};

struct cas_obj_label_map {
	const char *name;
	enum cas_obj_label type;
};

static const struct cas_obj_label_map cas_obj_label_map[] = {
	{ "nss_config", OBJ_NSS_CONFIG }, { "net_resolve", OBJ_NET_RESOLVE },
	{ "net_services", OBJ_NET_SERVICES }, { "group_db", OBJ_GROUP_DB },
	{ "net_protocols", OBJ_NET_PROTOCOLS },
	{ "pwd_public", OBJ_PWD_PUBLIC }, { "pwd_shadow", OBJ_PWD_SHADOW },
	{ "sys_time", OBJ_SYS_TIME }, { "sys_log", OBJ_SYS_LOG },
	{ NULL, OBJ_NONE }
};

/* ==========================================================
 * File Path Maps
 * ========================================================== */

struct obj_file_map {
	const char *path;
	enum cas_obj_label obj_type;
};

/* The Master List of File Classifications */
static const struct obj_file_map obj_file_map[] = {
	/* NSS Config (Used by DNS, GRP, NETDB, PWD) */
	{ "/etc/nsswitch.conf", OBJ_NSS_CONFIG },

	/* DNS service */
	{ "/etc/hosts", OBJ_NET_RESOLVE },
	{ "/etc/resolv.conf", OBJ_NET_RESOLVE },

	/* NETDB service (Services) */
	{ "/etc/services", OBJ_NET_SERVICES },

	/* GRP Service */
	{ "/etc/group", OBJ_GROUP_DB },
	{ "/var/db/cache/group.cache", OBJ_GROUP_DB },

	/* NETDB service (Protocols) */
	{ "/etc/protocols", OBJ_NET_PROTOCOLS },

	/* PWD Public Info (Used by PWD, SYSCTL, SYSLOG) */
	{ "/etc/pwd.db", OBJ_PWD_PUBLIC },

	/* PWD Shadow (Sensitive!) */
	{ "/etc/spwd.db", OBJ_PWD_SHADOW },

	/* SYSLOG / Time */
	{ "/etc/localtime", OBJ_SYS_TIME }, { "/var/run/log", OBJ_SYS_LOG },

	{ NULL, OBJ_NONE } /* Sentinel */
};

#endif
