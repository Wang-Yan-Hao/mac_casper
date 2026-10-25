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
/* ddb */
/* devfs */
/* ifnet */
int
casper_mpo_ifnet_check_relabel_t(struct ucred *cred, struct ifnet *ifp,
    struct label *ifplabel, struct label *newlabel)
{
	return casper_deny_default(cred);
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
