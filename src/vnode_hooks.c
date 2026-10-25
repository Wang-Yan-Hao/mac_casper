#include "internal.h"

/* vnode */
int
casper_mpo_vnode_check_access_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_chdir_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_chroot_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_deleteacl_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_deleteextattr_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_exec_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp, struct label *execlabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_getacl_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_getextattr_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_link_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_listextattr_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_mmap_t(struct ucred *cred, struct vnode *vp,
    struct label *label, int prot, int flags)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_mprotect_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_poll_t(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel)
{
	return casper_deny_default(active_cred);
}
int
casper_mpo_vnode_check_readdir_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_rename_from_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_rename_to_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    int samedir, struct componentname *cnp)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_revoke_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_setacl_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type, struct acl *acl)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_setflags_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, u_long flags)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_setmode_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, mode_t mode)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_setowner_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, uid_t uid, gid_t gid)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_setutimes_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct timespec atime, struct timespec mtime)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_unlink_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	return casper_deny_default(cred);
}
int
casper_mpo_vnode_check_write_t(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel)
{
	return casper_deny_default(active_cred);
}
int
casper_mpo_vnode_execve_will_transition_t(struct ucred *old, struct vnode *vp,
    struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel)
{
	return casper_deny_default(old);
}

/* vnode check */
int
casper_mpo_vnode_check_open(struct ucred *cred, struct vnode *vp,
    struct label *label, int acc_mode)
{
	struct mac_casper *subj, *obj;

	subj = casper_get_label(cred);
	if (subj == NULL)
		return (0);

	obj = SLOT(label);
	if (obj == NULL) // Casper label process can't read other file
		return (EACCES);

	return casper_check_allowed_open(subj, obj);
}
int
casper_mpo_vnode_check_create_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp, struct vattr *vap)
{
	struct mac_casper *obj = casper_get_label(cred);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_DNS || obj->type == SUB_NET ||
	    obj->type == SUB_GRP || obj->type == SUB_NETDB ||
	    obj->type == SUB_PWD || obj->type == SUB_SYSCTL ||
	    obj->type == SUB_SYSLOG)
		return (EACCES);

	return (0);
}
int
casper_mpo_vnode_check_read_t(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel)
{
	struct mac_casper *obj = casper_get_label(active_cred);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_FILEARGS)
		return (EACCES);

	return (0);
}
int
casper_mpo_vnode_check_stat_t(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel)
{
	struct mac_casper *obj = casper_get_label(active_cred);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_DNS || obj->type == SUB_NET ||
	    obj->type == SUB_FILEARGS || obj->type == SUB_GRP ||
	    obj->type == SUB_NETDB || obj->type == SUB_PWD)
		return (0);
	else if (obj->type == SUB_SYSCTL || obj->type == SUB_SYSLOG)
		return (EACCES);

	return (0);
}

/* DEBUG to print open file */
int
casper_mpo_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct componentname *cnp)
{
	struct mac_casper *subj = SLOT(cred->cr_label);

	if (subj == NULL || subj->type == SUB_NONE)
		return (0);

	printf(
	    "Casper Lookup: Subject=%d is looking for [%.*s] in dir_vnode=%p\n",
	    subj->type, (int)cnp->cn_namelen, cnp->cn_nameptr, dvp);

	return (0);
}
