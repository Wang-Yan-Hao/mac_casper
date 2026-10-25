#include "internal.h"

/* cred */
int
casper_mpo_cred_check_setaudit_t(struct ucred *cred, struct auditinfo *ai)
{
	return casper_deny_default(cred);
}
int
casper_mpo_cred_check_setaudit_addr_t(struct ucred *cred,
    struct auditinfo_addr *aia)
{
	return casper_deny_default(cred);
}
int
casper_mpo_cred_check_setauid_t(struct ucred *cred, uid_t auid)
{
	return casper_deny_default(cred);
}
int
casper_mpo_cred_check_setcred_t(u_int flags, const struct ucred *old_cred,
    struct ucred *new_cred)
{
	return casper_deny_default(old_cred);
}
int
casper_mpo_cred_check_setegid_t(struct ucred *cred, gid_t egid)
{
	return casper_deny_default(cred);
}
int
casper_mpo_cred_check_seteuid_t(struct ucred *cred, uid_t euid)
{
	return casper_deny_default(cred);
}
int
casper_po_cred_check_setgid_t(struct ucred *cred, gid_t gid)
{
	return casper_deny_default(cred);
}
int
casper_mpo_cred_check_setgroups_t(struct ucred *cred, int ngroups,
    gid_t *gidset)
{
	return casper_deny_default(cred);
}
int
casper_mpo_cred_check_setregid_t(struct ucred *cred, gid_t rgid, gid_t egid)
{
	return casper_deny_default(cred);
}
int
casper_mpo_cred_check_setresgid_t(struct ucred *cred, gid_t rgid, gid_t egid,
    gid_t sgid)
{
	return casper_deny_default(cred);
}
int
casper_mpo_cred_check_setresuid_t(struct ucred *cred, uid_t ruid, uid_t euid,
    uid_t suid)
{
	return casper_deny_default(cred);
}
int
casper_mpo_cred_check_setreuid_t(struct ucred *cred, uid_t ruid, uid_t euid)
{
	return casper_deny_default(cred);
}
int
casper_mpo_cred_check_setuid_t(struct ucred *cred, uid_t uid)
{
	return casper_deny_default(cred);
}
int
casper_mpo_cred_check_visible_t(struct ucred *cr1, struct ucred *cr2)
{
	struct mac_casper *obj = casper_get_label(cr1);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_DNS || obj->type == SUB_NET ||
		obj->type == SUB_FILEARGS || obj->type == SUB_GRP ||
		obj->type == SUB_NETDB || obj->type == SUB_PWD ||
		obj->type == SUB_SYSLOG)
		return (EACCES);

	return (0);
}
