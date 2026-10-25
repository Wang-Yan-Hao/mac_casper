#include "internal.h"

/* Helper function */
struct mac_casper *
casper_get_label(const struct ucred *cred)
{
	if (cred == NULL || cred->cr_label == NULL)
		return NULL;

	struct mac_casper *label = SLOT(cred->cr_label);
	return label;
}
int
casper_deny_default(const struct ucred *cred)
{
	struct mac_casper *obj = casper_get_label(cred);

	if (obj == NULL)
		return (0);

	if (obj->type > SUB_NONE && obj->type < SUB_LABEL_LEN)
		return (EACCES);

	return (0);
}

/* bpfdsec */
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
/* ddb */
/* devfs */
/* ifnet */
int
casper_mpo_ifnet_check_relabel_t(struct ucred *cred, struct ifnet *ifp,
    struct label *ifplabel, struct label *newlabel)
{
	return casper_deny_default(cred);
}
/* inpcb */
int
casper_mpo_inpcb_check_visible_t(struct ucred *cred, struct inpcb *inp,
    struct label *inplabel)
{
	struct mac_casper *obj = casper_get_label(cred);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_DNS || obj->type == SUB_NET ||
		obj->type == SUB_FILEARGS || obj->type == SUB_GRP ||
		obj->type == SUB_NETDB || obj->type == SUB_PWD ||
		obj->type == SUB_SYSLOG)
		return (EACCES);

	return (0);
}
/* ip6q */
/* jail */
int
casper_mpo_ip4_check_jail_t(struct ucred *cred, const struct in_addr *ia,
    struct ifnet *ifp)
{
	return casper_deny_default(cred);
}
int
casper_mpo_ip6_check_jail_t(struct ucred *cred, const struct in6_addr *ia6,
    struct ifnet *ifp)
{
	return casper_deny_default(cred);
}
/* ipq */
/* kdb */
/* kenv */
int
casper_mpo_kenv_check_dump_t(struct ucred *cred)
{
	return casper_deny_default(cred);
}
int
casper_mpo_kenv_check_get_t(struct ucred *cred, char *name)
{
	return casper_deny_default(cred);
}
int
casper_mpo_kenv_check_set_t(struct ucred *cred, char *name, char *value)
{
	return casper_deny_default(cred);
}
int
casper_mpo_kenv_check_unset_t(struct ucred *cred, char *name)
{
	return casper_deny_default(cred);
}
/* kld */
int
casper_mpo_kld_check_load_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_kld_check_stat_t(struct ucred *cred)
{
	return casper_deny_default(cred);
}
/* mbuf */
/* mount */
int
casper_mpo_mount_check_stat_t(struct ucred *cred, struct mount *mp,
    struct label *mplabel)
{
	return casper_deny_default(cred);
}
/* netinet */
/* netinet6 */
/* pipe */
int
casper_mpo_pipe_check_ioctl_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, unsigned long cmd, void *data)
{
	return casper_deny_default(cred);
}
int
casper_mpo_pipe_check_poll_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_pipe_check_read_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_pipe_check_relabel_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, struct label *newlabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_pipe_check_stat_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_pipe_check_write_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	return casper_deny_default(cred);
}
/* posixsem */
int
casper_mpo_posixsem_check_getvalue_t(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	return casper_deny_default(active_cred);
}
int
casper_mpo_posixsem_check_open_t(struct ucred *cred, struct ksem *ks,
    struct label *kslabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_posixsem_check_post_t(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	return casper_deny_default(active_cred);
}
int
casper_mpo_posixsem_check_setmode_t(struct ucred *cred, struct ksem *ks,
    struct label *shmlabel, mode_t mode)
{
	return casper_deny_default(cred);
}
int
casper_mpo_posixsem_check_setowner_t(struct ucred *cred, struct ksem *ks,
    struct label *shmlabel, uid_t uid, gid_t gid)
{
	return casper_deny_default(cred);
}
int
casper_mpo_posixsem_check_stat_t(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	return casper_deny_default(active_cred);
}
int
casper_mpo_posixsem_check_unlink_t(struct ucred *cred, struct ksem *ks,
    struct label *kslabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_posixsem_check_wait_t(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	return casper_deny_default(active_cred);
}
/* posixshm */
int
casper_mpo_posixshm_check_create_t(struct ucred *cred, const char *path)
{
	return casper_deny_default(cred);
}
int
casper_mpo_posixshm_check_mmap_t(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, int prot, int flags)
{
	return casper_deny_default(cred);
}
int
casper_mpo_posixshm_check_open_t(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, accmode_t accmode)
{
	return casper_deny_default(cred);
}
int
casper_mpo_posixshm_check_read_t(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel)
{
	return casper_deny_default(active_cred);
}
int
casper_mpo_posixshm_check_setmode_t(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, mode_t mode)
{
	return casper_deny_default(cred);
}
int
casper_mpo_posixshm_check_setowner_t(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, uid_t uid, gid_t gid)
{
	return casper_deny_default(cred);
}
int
casper_mpo_posixshm_check_stat_t(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel)
{
	return casper_deny_default(active_cred);
}
int
casper_mpo_posixshm_check_truncate_t(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel)
{
	return casper_deny_default(active_cred);
}
int
casper_mpo_posixshm_check_unlink_t(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_posixshm_check_write_t(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel)
{
	return casper_deny_default(active_cred);
}
/* proc */
int
casper_mpo_proc_check_debug_t(struct ucred *cred, struct proc *p)
{
	return casper_deny_default(cred);
}
int
casper_mpo_proc_check_sched_t(struct ucred *cred, struct proc *p)
{
	return casper_deny_default(cred);
}
int
casper_mpo_proc_check_signal_t(struct ucred *cred, struct proc *proc,
    int signum)
{
	return casper_deny_default(cred);
}
int
casper_mpo_proc_check_wait_t(struct ucred *cred, struct proc *proc)
{
	return casper_deny_default(cred);
}
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
/* sysvmsg */
/* sysvmsq */
int
casper_mpo_sysvmsq_check_msgmsq_t(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel, struct msqid_kernel *msqkptr,
    struct label *msqklabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_sysvmsq_check_msgrcv_t(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_sysvmsq_check_msgrmid_t(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_sysvmsq_check_msqget_t(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_sysvmsq_check_msqctl_t(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel, int cmd)
{
	return casper_deny_default(cred);
}
int
casper_mpo_sysvmsq_check_msqrcv_t(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_sysvmsq_check_msqsnd_t(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel)
{
	return casper_deny_default(cred);
}
/* sysvsem */
int
casper_mpo_sysvsem_check_semctl_t(struct ucred *cred,
    struct semid_kernel *semakptr, struct label *semaklabel, int cmd)
{
	return casper_deny_default(cred);
}
int
casper_mpo_sysvsem_check_semget_t(struct ucred *cred,
    struct semid_kernel *semakptr, struct label *semaklabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_sysvsem_check_semop_t(struct ucred *cred,
    struct semid_kernel *semakptr, struct label *semaklabel, size_t accesstype)
{
	return casper_deny_default(cred);
}
/* sysvshm */
int
casper_mpo_sysvshm_check_shmat_t(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel, int shmflg)
{
	return casper_deny_default(cred);
}
int
casper_mpo_sysvshm_check_shmctl_t(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel, int cmd)
{
	return casper_deny_default(cred);
}
int
casper_mpo_sysvshm_check_shmdt_t(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_sysvshm_check_shmget_t(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel, int shmflg)
{
	return casper_deny_default(cred);
}
/* thread */
