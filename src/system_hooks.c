#include "internal.h"

/* system */
int
casper_mpo_system_check_acct_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_system_check_audit_t(struct ucred *cred, void *record, int length)
{
	return casper_deny_default(cred);
}
int
casper_mpo_system_check_auditctl_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_system_check_auditon_t(struct ucred *cred, int cmd)
{
	return casper_deny_default(cred);
}
int
casper_mpo_system_check_reboot_t(struct ucred *cred, int howto)
{
	return casper_deny_default(cred);
}
int
casper_mpo_system_check_swapon_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_system_check_swapoff_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_system_check_sysctl_t(struct ucred *cred, struct sysctl_oid *oidp,
    void *arg1, int arg2, struct sysctl_req *req)
{
	struct mac_casper *obj = casper_get_label(cred);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_GRP)
		return (EACCES);

	return (0);
}
