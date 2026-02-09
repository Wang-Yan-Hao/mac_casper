#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/domain.h>
#include <sys/extattr.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/mac.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/sbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/uma.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>
#include <security/mac/mac_syscalls.h>

#include "checker.h"
#include "label.h"
#include "mac_casper.h"

static int casper_slot;
static uma_zone_t zone_casper;

/* Helper function */
static inline struct mac_casper *
casper_get_label(const struct ucred *cred)
{
	if (cred == NULL || cred->cr_label == NULL)
		return NULL;

	struct mac_casper *label = SLOT(cred->cr_label);
	return label;
}
static int
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
static int
casper_mpo_cred_check_setaudit_t(struct ucred *cred, struct auditinfo *ai)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_cred_check_setaudit_addr_t(struct ucred *cred,
    struct auditinfo_addr *aia)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_cred_check_setauid_t(struct ucred *cred, uid_t auid)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_cred_check_setcred_t(u_int flags, const struct ucred *old_cred,
    struct ucred *new_cred)
{
	return casper_deny_default(old_cred);
}
static int
casper_mpo_cred_check_setegid_t(struct ucred *cred, gid_t egid)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_cred_check_seteuid_t(struct ucred *cred, uid_t euid)
{
	return casper_deny_default(cred);
}
static int
casper_po_cred_check_setgid_t(struct ucred *cred, gid_t gid)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_cred_check_setgroups_t(struct ucred *cred, int ngroups,
    gid_t *gidset)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_cred_check_setregid_t(struct ucred *cred, gid_t rgid, gid_t egid)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_cred_check_setresgid_t(struct ucred *cred, gid_t rgid, gid_t egid,
    gid_t sgid)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_cred_check_setresuid_t(struct ucred *cred, uid_t ruid, uid_t euid,
    uid_t suid)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_cred_check_setreuid_t(struct ucred *cred, uid_t ruid, uid_t euid)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_cred_check_setuid_t(struct ucred *cred, uid_t uid)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_cred_check_visible_t(struct ucred *cr1, struct ucred *cr2)
{
	return casper_deny_default(cr1);
}
/* ddb */
/* devfs */
/* ifnet */
static int
casper_mpo_ifnet_check_relabel_t(struct ucred *cred, struct ifnet *ifp,
    struct label *ifplabel, struct label *newlabel)
{
	return casper_deny_default(cred);
}
/* inpcb */
static int
casper_mpo_inpcb_check_visible_t(struct ucred *cred, struct inpcb *inp,
    struct label *inplabel)
{
	return casper_deny_default(cred);
}
/* ip6q */
/* jail */
static int
casper_mpo_ip4_check_jail_t(struct ucred *cred, const struct in_addr *ia,
    struct ifnet *ifp)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_ip6_check_jail_t(struct ucred *cred, const struct in6_addr *ia6,
    struct ifnet *ifp)
{
	return casper_deny_default(cred);
}
/* ipq */
/* kdb */
/* kenv */
static int
casper_mpo_kenv_check_dump_t(struct ucred *cred)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_kenv_check_get_t(struct ucred *cred, char *name)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_kenv_check_set_t(struct ucred *cred, char *name, char *value)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_kenv_check_unset_t(struct ucred *cred, char *name)
{
	return casper_deny_default(cred);
}
/* kld */
static int
casper_mpo_kld_check_load_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_kld_check_stat_t(struct ucred *cred)
{
	return casper_deny_default(cred);
}
/* mbuf */
/* mount */
static int
casper_mpo_mount_check_stat_t(struct ucred *cred, struct mount *mp,
    struct label *mplabel)
{
	return casper_deny_default(cred);
}
/* netinet */
/* netinet6 */
/* pipe */
static int
casper_mpo_pipe_check_ioctl_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, unsigned long cmd, void *data)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_pipe_check_poll_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_pipe_check_read_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_pipe_check_relabel_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, struct label *newlabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_pipe_check_stat_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_pipe_check_write_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	return casper_deny_default(cred);
}
/* posixsem */
static int
casper_mpo_posixsem_check_getvalue_t(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	return casper_deny_default(active_cred);
}
static int
casper_mpo_posixsem_check_open_t(struct ucred *cred, struct ksem *ks,
    struct label *kslabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_posixsem_check_post_t(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	return casper_deny_default(active_cred);
}
static int
casper_mpo_posixsem_check_setmode_t(struct ucred *cred, struct ksem *ks,
    struct label *shmlabel, mode_t mode)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_posixsem_check_setowner_t(struct ucred *cred, struct ksem *ks,
    struct label *shmlabel, uid_t uid, gid_t gid)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_posixsem_check_stat_t(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	return casper_deny_default(active_cred);
}
static int
casper_mpo_posixsem_check_unlink_t(struct ucred *cred, struct ksem *ks,
    struct label *kslabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_posixsem_check_wait_t(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel)
{
	return casper_deny_default(active_cred);
}
/* posixshm */
static int
casper_mpo_posixshm_check_create_t(struct ucred *cred, const char *path)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_posixshm_check_mmap_t(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, int prot, int flags)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_posixshm_check_open_t(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, accmode_t accmode)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_posixshm_check_read_t(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel)
{
	return casper_deny_default(active_cred);
}
static int
casper_mpo_posixshm_check_setmode_t(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, mode_t mode)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_posixshm_check_setowner_t(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, uid_t uid, gid_t gid)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_posixshm_check_stat_t(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel)
{
	return casper_deny_default(active_cred);
}
static int
casper_mpo_posixshm_check_truncate_t(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel)
{
	return casper_deny_default(active_cred);
}
static int
casper_mpo_posixshm_check_unlink_t(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_posixshm_check_write_t(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel)
{
	return casper_deny_default(active_cred);
}
/* proc */
static int
casper_mpo_proc_check_debug_t(struct ucred *cred, struct proc *p)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_proc_check_sched_t(struct ucred *cred, struct proc *p)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_proc_check_signal_t(struct ucred *cred, struct proc *proc,
    int signum)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_proc_check_wait_t(struct ucred *cred, struct proc *proc)
{
	return casper_deny_default(cred);
}
/* socket */
static int
casper_mpo_socket_check_accept_t(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_socket_check_bind_t(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_socket_check_connect_t(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa)
{
	struct mac_casper *obj = casper_get_label(cred);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_FILEARGS || obj->type == SUB_GRP ||
	    obj->type == SUB_NETDB || obj->type == SUB_PWD ||
	    obj->type == SUB_SYSCTL)
		return (EACCES);

	return (0);
}
static int
casper_mpo_socket_check_create_t(struct ucred *cred, int domain, int type,
    int protocol)
{
	struct mac_casper *obj = casper_get_label(cred);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_DNS)
		return (0);
	else if (obj->type == SUB_FILEARGS || obj->type == SUB_GRP ||
	    obj->type == SUB_NETDB || obj->type == SUB_PWD ||
	    obj->type == SUB_SYSCTL || obj->type == SUB_SYSLOG) {
		if (domain != PF_UNIX)
			return (EACCES);
		return (0);
	}

	return (0);
}
static int
casper_mpo_socket_check_listen_t(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_socket_check_poll_t(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct mac_casper *obj = casper_get_label(cred);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_FILEARGS || obj->type == SUB_GRP ||
	    obj->type == SUB_NETDB || obj->type == SUB_PWD ||
	    obj->type == SUB_SYSCTL || obj->type == SUB_SYSLOG) {
		if (so->so_proto->pr_domain->dom_family == AF_UNIX)
			return (0);
		return (EACCES);
	}

	return (0);
}
static int
casper_mpo_socket_check_receive_t(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct mac_casper *obj = casper_get_label(cred);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_FILEARGS || obj->type == SUB_GRP ||
	    obj->type == SUB_NETDB || obj->type == SUB_PWD ||
	    obj->type == SUB_SYSCTL || obj->type == SUB_SYSLOG) {
		if (so->so_proto->pr_domain->dom_family == AF_UNIX)
			return (0);
		return (EACCES);
	}

	return (0);
}
static int
casper_mpo_socket_check_relabel_t(struct ucred *cred, struct socket *so,
    struct label *solabel, struct label *newlabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_socket_check_send_t(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct mac_casper *obj = casper_get_label(cred);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_FILEARGS || obj->type == SUB_GRP ||
	    obj->type == SUB_NETDB || obj->type == SUB_PWD ||
	    obj->type == SUB_SYSCTL || obj->type == SUB_SYSLOG) {
		if (so->so_proto->pr_domain->dom_family == AF_UNIX)
			return (0);
		return (EACCES);
	}

	return (0);
}
static int
casper_mpo_socket_check_stat_t(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_socket_check_visible_t(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	return casper_deny_default(cred);
}
/* socketpeer */
/* syncache */
/* system */
static int
casper_mpo_system_check_acct_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_system_check_audit_t(struct ucred *cred, void *record, int length)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_system_check_auditctl_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_system_check_auditon_t(struct ucred *cred, int cmd)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_system_check_reboot_t(struct ucred *cred, int howto)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_system_check_swapon_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_system_check_swapoff_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_system_check_sysctl_t(struct ucred *cred, struct sysctl_oid *oidp,
    void *arg1, int arg2, struct sysctl_req *req)
{
	struct mac_casper *obj = casper_get_label(cred);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_DNS || obj->type == SUB_SYSCTL ||
	    obj->type == SUB_SYSLOG)
		return (0);
	else if (obj->type == SUB_FILEARGS || obj->type == SUB_GRP ||
	    obj->type == SUB_NETDB || obj->type == SUB_PWD)
		return (EACCES);

	return (0);
}
/* sysvmsg */
/* sysvmsq */
static int
casper_mpo_sysvmsq_check_msgmsq_t(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel, struct msqid_kernel *msqkptr,
    struct label *msqklabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_sysvmsq_check_msgrcv_t(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_sysvmsq_check_msgrmid_t(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_sysvmsq_check_msqget_t(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_sysvmsq_check_msqctl_t(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel, int cmd)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_sysvmsq_check_msqrcv_t(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_sysvmsq_check_msqsnd_t(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel)
{
	return casper_deny_default(cred);
}
/* sysvsem */
static int
casper_mpo_sysvsem_check_semctl_t(struct ucred *cred,
    struct semid_kernel *semakptr, struct label *semaklabel, int cmd)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_sysvsem_check_semget_t(struct ucred *cred,
    struct semid_kernel *semakptr, struct label *semaklabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_sysvsem_check_semop_t(struct ucred *cred,
    struct semid_kernel *semakptr, struct label *semaklabel, size_t accesstype)
{
	return casper_deny_default(cred);
}
/* sysvshm */
static int
casper_mpo_sysvshm_check_shmat_t(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel, int shmflg)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_sysvshm_check_shmctl_t(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel, int cmd)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_sysvshm_check_shmdt_t(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_sysvshm_check_shmget_t(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel, int shmflg)
{
	return casper_deny_default(cred);
}
/* thread */

/* vnode */
static int
casper_mpo_vnode_check_access_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_chdir_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_chroot_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_deleteacl_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_deleteextattr_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_exec_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp, struct label *execlabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_getacl_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_getextattr_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_link_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_listextattr_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_mmap_t(struct ucred *cred, struct vnode *vp,
    struct label *label, int prot, int flags)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_mprotect_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_poll_t(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel)
{
	return casper_deny_default(active_cred);
}
static int
casper_mpo_vnode_check_readdir_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_rename_from_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_rename_to_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    int samedir, struct componentname *cnp)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_revoke_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_setacl_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type, struct acl *acl)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_setflags_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, u_long flags)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_setmode_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, mode_t mode)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_setowner_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, uid_t uid, gid_t gid)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_setutimes_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct timespec atime, struct timespec mtime)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_unlink_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_write_t(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel)
{
	return casper_deny_default(active_cred);
}
static int
casper_mpo_vnode_execve_will_transition_t(struct ucred *old, struct vnode *vp,
    struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel)
{
	return casper_deny_default(old);
}

/* vnode check */
static int
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
static int
casper_mpo_vnode_check_create_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp, struct vattr *vap)
{
	struct mac_casper *obj = casper_get_label(cred);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_FILEARGS)
		return (0);
	else if (obj->type == SUB_DNS || obj->type == SUB_GRP ||
	    obj->type == SUB_NETDB || obj->type == SUB_PWD ||
	    obj->type == SUB_SYSCTL || obj->type == SUB_SYSLOG)
		return (EACCES);

	return (0);
}
static int
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
static int
casper_mpo_vnode_check_stat_t(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel)
{
	struct mac_casper *obj = casper_get_label(active_cred);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_DNS || obj->type == SUB_FILEARGS ||
	    obj->type == SUB_GRP || obj->type == SUB_NETDB ||
	    obj->type == SUB_PWD)
		return (0);
	else if (obj->type == SUB_SYSCTL || obj->type == SUB_SYSLOG)
		return (EACCES);

	return (0);
}

/* init */
static void
casper_init(struct mac_policy_conf *conf)
{
	/* Check if zone_casper is already created */
	zone_casper = uma_zcreate("mac_casper", sizeof(struct mac_casper), NULL,
	    NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
	if (zone_casper == NULL)
		return;
}
static void
casper_destroy(struct mac_policy_conf *mpc)
{
	if (zone_casper != NULL) {
		uma_zdestroy(zone_casper);
		zone_casper = NULL;
	}
}

/* Common label function */
static void
casper_destroy_label(struct label *label)
{
	struct mac_casper *mpl;

	mpl = SLOT(label);

	if (mpl != NULL) {
		uma_zfree(zone_casper, mpl);
		SLOT_SET(label, NULL);
	}
}

/* vnode label*/
static void
casper_vnode_init_label(struct label *label)
{
	struct mac_casper *c_label;

	c_label = uma_zalloc(zone_casper, M_WAITOK | M_ZERO);
	if (c_label == NULL)
		return;

	c_label->type = SUB_NONE;
	SLOT_SET(label, c_label);

	return;
}
static int
casper_mpo_vnode_check_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel)
{
	return 0;
}
static void
casper_mpo_vnode_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *label)
{
	struct mac_casper *src, *dst;

	src = SLOT(label);
	dst = SLOT(vplabel);

	if (src == NULL || dst == NULL)
		return;

	dst->type = src->type;
}
static void
casper_mpo_vnode_copy_label(struct label *src, struct label *dest)
{
	struct mac_casper *s, *d;
	s = SLOT(src);
	d = SLOT(dest);

	if (s == NULL || d == NULL)
		return;

	*d = *s;
}
static int
casper_mpo_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	return 0;
}
static int
casper_mpo_vnode_setlabel_extattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *intlabel)
{
	struct mac_casper *src;
	size_t buflen;
	int error;

	src = SLOT(intlabel);
	buflen = sizeof(struct mac_casper);

	if (src == NULL)
		return (EINVAL);

	error = vn_extattr_set(vp, IO_NODELOCKED, MAC_SUB_EXTATTR_NAMESPACE,
	    MAC_SUB_EXTATTR_NAME, buflen, (char *)src, curthread);

	return (error);
}
static int
casper_mpo_vnode_associate_extattr(struct mount *mp, struct label *mplabel,
    struct vnode *vp, struct label *vplabel)
{
	struct mac_casper *dest;
	int error;
	int len;

	dest = SLOT(vplabel);

	if (dest == NULL)
		return 0;

	len = sizeof(struct mac_casper);

	error = vn_extattr_get(vp, IO_NODELOCKED, MAC_SUB_EXTATTR_NAMESPACE,
	    MAC_SUB_EXTATTR_NAME, &len,
	    (char *)dest, // 直接寫入結構指標
	    curthread);

	if (error == ENOATTR || error == EOPNOTSUPP) {
		/* The file on disk has no extended attribute.
		 * We simply mark the memory label as NONE (Empty).
		 * We return 0 (Success) so the OS lets the file load normally.
		 */
		dest->type = SUB_NONE;
		return (0);
	}

	if (error)
		return (error);

	if (len != sizeof(struct mac_casper))
		/* Data on disk is wrong size? Treat as empty. */
		dest->type = SUB_NONE;

	return (0);
}
static int
casper_mpo_vnode_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{
	struct mac_casper *mpl;
	enum cas_obj_label found_type = OBJ_NONE;

	if (element_data == NULL || element_name == NULL)
		return (EINVAL);

	if (strcmp(MAC_CASPER_LABEL_NAME, element_name) != 0)
		return (0);

	for (int i = 0; cas_obj_label_map[i].name != NULL; i++) {
		if (strcmp(element_data, cas_obj_label_map[i].name) == 0) {
			found_type = cas_obj_label_map[i].type;
			break;
		}
	}

	if (found_type == OBJ_NONE)
		return (EINVAL);

	mpl = SLOT(label);

	if (mpl == NULL)
		return (ENOMEM);

	mpl->type = found_type;
	(*claimed)++;

	return (0);
}
static int
casper_mpo_vnode_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{
	struct mac_casper *mpl;
	const char *result_name = NULL;

	if (strcmp(MAC_CASPER_LABEL_NAME, element_name) != 0)
		return (0);

	mpl = SLOT(label);

	if (mpl == NULL)
		return (0);

	for (int i = 0; cas_obj_label_map[i].name != NULL; i++) {
		if (cas_obj_label_map[i].type == mpl->type) {
			result_name = cas_obj_label_map[i].name;
			break;
		}
	}

	if (result_name != NULL) {
		if (sbuf_printf(sb, "%s", result_name) == -1)
			return (ENOMEM);

		(*claimed)++;
	}

	return (0);
}

/* cred label */
static void
casper_cred_init_label(struct label *label)
{
	return;
}
static void
casper_cred_relabel(struct ucred *cred, struct label *newlabel)
{
	struct mac_casper *src, *dst;

	if (cred == NULL || newlabel == NULL)
		return;

	dst = SLOT(cred->cr_label);
	src = SLOT(newlabel);

	if (src == NULL)
		return;

	if (dst == NULL) {
		dst = uma_zalloc(zone_casper, M_NOWAIT | M_ZERO);
		if (dst == NULL)
			return;
		SLOT_SET(cred->cr_label, dst);
	}

	dst->type = src->type;
}
static int
casper_mpo_cred_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{
	struct mac_casper *mpl;
	enum cas_sub_label found_type = SUB_NONE;

	if (element_data == NULL || element_name == NULL)
		return (EINVAL);

	if (strcmp(MAC_CASPER_LABEL_NAME, element_name) != 0)
		return (0);

	for (int i = 0; cas_sub_label_map[i].name != NULL; i++) {
		if (strcmp(element_data, cas_sub_label_map[i].name) == 0) {
			found_type = cas_sub_label_map[i].type;
			break;
		}
	}

	if (found_type == SUB_NONE)
		return (EINVAL);

	mpl = SLOT(label);

	if (mpl == NULL) {
		mpl = uma_zalloc(zone_casper, M_NOWAIT | M_ZERO);

		if (mpl == NULL)
			return (ENOMEM);

		SLOT_SET(label, mpl);
	}

	mpl->type = found_type;
	(*claimed)++;

	return (0);
}
static int
casper_mpo_cred_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{
	struct mac_casper *mpl;
	const char *result_name = NULL;

	if (strcmp(MAC_CASPER_LABEL_NAME, element_name) != 0)
		return (0);

	mpl = SLOT(label);

	if (mpl == NULL)
		return (0);

	for (int i = 0; cas_sub_label_map[i].name != NULL; i++) {
		if (cas_sub_label_map[i].type == mpl->type) {
			result_name = cas_sub_label_map[i].name;
			break;
		}
	}

	if (result_name != NULL) {
		if (sbuf_printf(sb, "%s", result_name) == -1)
			return (ENOMEM);

		(*claimed)++;
	}

	return (0);
}

/* DEBUG to print open file */
static int
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

/* Base structure */
static struct mac_policy_ops casper_mac_policy_ops = {
	/* init */
	.mpo_init = casper_init,       // Enable
	.mpo_destroy = casper_destroy, // Enable
	/* bpfdsec */
	/* cred */
	.mpo_cred_check_setaudit = casper_mpo_cred_check_setaudit_t,
	.mpo_cred_check_setaudit_addr = casper_mpo_cred_check_setaudit_addr_t,
	.mpo_cred_check_setauid = casper_mpo_cred_check_setauid_t,
	.mpo_cred_check_setcred = casper_mpo_cred_check_setcred_t,
	.mpo_cred_check_setegid = casper_mpo_cred_check_setegid_t,
	.mpo_cred_check_seteuid = casper_mpo_cred_check_seteuid_t,
	.mpo_cred_check_setgid = casper_po_cred_check_setgid_t,
	.mpo_cred_check_setgroups = casper_mpo_cred_check_setgroups_t,
	.mpo_cred_check_setregid = casper_mpo_cred_check_setregid_t,
	.mpo_cred_check_setresgid = casper_mpo_cred_check_setresgid_t,
	.mpo_cred_check_setresuid = casper_mpo_cred_check_setresuid_t,
	.mpo_cred_check_setreuid = casper_mpo_cred_check_setreuid_t,
	.mpo_cred_check_setuid = casper_mpo_cred_check_setuid_t,
	.mpo_cred_check_visible = casper_mpo_cred_check_visible_t,
	/* ddb */
	/* devfs */
	/* ifnet */
	.mpo_ifnet_check_relabel = casper_mpo_ifnet_check_relabel_t,
	/* inpcb */
	.mpo_inpcb_check_visible = casper_mpo_inpcb_check_visible_t,
	/* ip6q */
	/* jail */
	.mpo_ip4_check_jail = casper_mpo_ip4_check_jail_t,
	.mpo_ip6_check_jail = casper_mpo_ip6_check_jail_t,
	/* ipq */
	/* kdb */
	/* kenv */
	.mpo_kenv_check_dump = casper_mpo_kenv_check_dump_t,
	.mpo_kenv_check_get = casper_mpo_kenv_check_get_t,
	.mpo_kenv_check_set = casper_mpo_kenv_check_set_t,
	.mpo_kenv_check_unset = casper_mpo_kenv_check_unset_t,
	/* kld */
	.mpo_kld_check_load = casper_mpo_kld_check_load_t,
	.mpo_kld_check_stat = casper_mpo_kld_check_stat_t,
	/* mbuf */
	/* mount */
	.mpo_mount_check_stat = casper_mpo_mount_check_stat_t,
	/* netinet */
	/* netinet6 */
	/* pipe */
	.mpo_pipe_check_ioctl = casper_mpo_pipe_check_ioctl_t,
	.mpo_pipe_check_poll = casper_mpo_pipe_check_poll_t,
	.mpo_pipe_check_read = casper_mpo_pipe_check_read_t,
	.mpo_pipe_check_relabel = casper_mpo_pipe_check_relabel_t,
	.mpo_pipe_check_stat = casper_mpo_pipe_check_stat_t,
	// If run syscall test, it sholud be comment to let
	// python get the output
	.mpo_pipe_check_write = casper_mpo_pipe_check_write_t,
	/* posixsem */
	.mpo_posixsem_check_getvalue = casper_mpo_posixsem_check_getvalue_t,
	.mpo_posixsem_check_open = casper_mpo_posixsem_check_open_t,
	.mpo_posixsem_check_post = casper_mpo_posixsem_check_post_t,
	.mpo_posixsem_check_setmode = casper_mpo_posixsem_check_setmode_t,
	.mpo_posixsem_check_setowner = casper_mpo_posixsem_check_setowner_t,
	.mpo_posixsem_check_stat = casper_mpo_posixsem_check_stat_t,
	.mpo_posixsem_check_unlink = casper_mpo_posixsem_check_unlink_t,
	.mpo_posixsem_check_wait = casper_mpo_posixsem_check_wait_t,
	/* posixshm */
	.mpo_posixshm_check_create = casper_mpo_posixshm_check_create_t,
	.mpo_posixshm_check_mmap = casper_mpo_posixshm_check_mmap_t,
	.mpo_posixshm_check_open = casper_mpo_posixshm_check_open_t,
	.mpo_posixshm_check_read = casper_mpo_posixshm_check_read_t,
	.mpo_posixshm_check_setmode = casper_mpo_posixshm_check_setmode_t,
	.mpo_posixshm_check_setowner = casper_mpo_posixshm_check_setowner_t,
	.mpo_posixshm_check_stat = casper_mpo_posixshm_check_stat_t,
	.mpo_posixshm_check_truncate = casper_mpo_posixshm_check_truncate_t,
	.mpo_posixshm_check_unlink = casper_mpo_posixshm_check_unlink_t,
	.mpo_posixshm_check_write = casper_mpo_posixshm_check_write_t,
	/* proc */
	.mpo_proc_check_debug = casper_mpo_proc_check_debug_t,
	.mpo_proc_check_sched = casper_mpo_proc_check_sched_t,
	.mpo_proc_check_signal = casper_mpo_proc_check_signal_t,
	.mpo_proc_check_wait = casper_mpo_proc_check_wait_t,
	/* socket */
	.mpo_socket_check_accept = casper_mpo_socket_check_accept_t,
	.mpo_socket_check_bind = casper_mpo_socket_check_bind_t,
	.mpo_socket_check_connect = casper_mpo_socket_check_connect_t, // Check
	.mpo_socket_check_create =
	    casper_mpo_socket_check_create_t, // Capser need
	.mpo_socket_check_listen = casper_mpo_socket_check_listen_t,
	.mpo_socket_check_poll = casper_mpo_socket_check_poll_t, // Casper need
	.mpo_socket_check_receive =
	    casper_mpo_socket_check_receive_t, // Casper need
	.mpo_socket_check_relabel = casper_mpo_socket_check_relabel_t,
	.mpo_socket_check_send = casper_mpo_socket_check_send_t, // Casper need
	.mpo_socket_check_stat = casper_mpo_socket_check_stat_t,
	.mpo_socket_check_visible = casper_mpo_socket_check_visible_t,
	/* syncache */
	/* socketpeer */
	/* system */
	.mpo_system_check_acct = casper_mpo_system_check_acct_t,
	.mpo_system_check_audit = casper_mpo_system_check_audit_t,
	.mpo_system_check_auditctl = casper_mpo_system_check_auditctl_t,
	.mpo_system_check_auditon = casper_mpo_system_check_auditon_t,
	.mpo_system_check_reboot = casper_mpo_system_check_reboot_t,
	.mpo_system_check_swapon = casper_mpo_system_check_swapon_t,
	.mpo_system_check_swapoff = casper_mpo_system_check_swapoff_t,
	.mpo_system_check_sysctl = casper_mpo_system_check_sysctl_t,
	/* sysvmsg */
	/* sysvmsq */
	.mpo_sysvmsq_check_msgmsq = casper_mpo_sysvmsq_check_msgmsq_t,
	.mpo_sysvmsq_check_msgrcv = casper_mpo_sysvmsq_check_msgrcv_t,
	.mpo_sysvmsq_check_msgrmid = casper_mpo_sysvmsq_check_msgrmid_t,
	.mpo_sysvmsq_check_msqget = casper_mpo_sysvmsq_check_msqget_t,
	.mpo_sysvmsq_check_msqctl = casper_mpo_sysvmsq_check_msqctl_t,
	.mpo_sysvmsq_check_msqrcv = casper_mpo_sysvmsq_check_msqrcv_t,
	.mpo_sysvmsq_check_msqsnd = casper_mpo_sysvmsq_check_msqsnd_t,
	/* sysvsem */
	.mpo_sysvsem_check_semctl = casper_mpo_sysvsem_check_semctl_t,
	.mpo_sysvsem_check_semget = casper_mpo_sysvsem_check_semget_t,
	.mpo_sysvsem_check_semop = casper_mpo_sysvsem_check_semop_t,
	/* sysvshm */
	.mpo_sysvshm_check_shmat = casper_mpo_sysvshm_check_shmat_t,
	.mpo_sysvshm_check_shmctl = casper_mpo_sysvshm_check_shmctl_t,
	.mpo_sysvshm_check_shmdt = casper_mpo_sysvshm_check_shmdt_t,
	.mpo_sysvshm_check_shmget = casper_mpo_sysvshm_check_shmget_t,
	/* thread */

	/* vnode disable */
	.mpo_vnode_check_access = casper_mpo_vnode_check_access_t,
	.mpo_vnode_check_chdir = casper_mpo_vnode_check_chdir_t,
	.mpo_vnode_check_chroot = casper_mpo_vnode_check_chroot_t,
	.mpo_vnode_check_deleteacl = casper_mpo_vnode_check_deleteacl_t,
	.mpo_vnode_check_deleteextattr = casper_mpo_vnode_check_deleteextattr_t,
	.mpo_vnode_check_exec = casper_mpo_vnode_check_exec_t,
	.mpo_vnode_check_getacl = casper_mpo_vnode_check_getacl_t,
	.mpo_vnode_check_getextattr = casper_mpo_vnode_check_getextattr_t,
	.mpo_vnode_check_link = casper_mpo_vnode_check_link_t,
	.mpo_vnode_check_listextattr = casper_mpo_vnode_check_listextattr_t,
	.mpo_vnode_check_mmap = casper_mpo_vnode_check_mmap_t,
	.mpo_vnode_check_mprotect = casper_mpo_vnode_check_mprotect_t,
	.mpo_vnode_check_poll = casper_mpo_vnode_check_poll_t,
	.mpo_vnode_check_readdir = casper_mpo_vnode_check_readdir_t,
	.mpo_vnode_check_rename_from = casper_mpo_vnode_check_rename_from_t,
	.mpo_vnode_check_rename_to = casper_mpo_vnode_check_rename_to_t,
	.mpo_vnode_check_revoke = casper_mpo_vnode_check_revoke_t,
	.mpo_vnode_check_setacl = casper_mpo_vnode_check_setacl_t,
	.mpo_vnode_check_setflags = casper_mpo_vnode_check_setflags_t,
	.mpo_vnode_check_setmode = casper_mpo_vnode_check_setmode_t,
	.mpo_vnode_check_setowner = casper_mpo_vnode_check_setowner_t,
	.mpo_vnode_check_setutimes = casper_mpo_vnode_check_setutimes_t,
	.mpo_vnode_check_unlink = casper_mpo_vnode_check_unlink_t,
	.mpo_vnode_check_write = casper_mpo_vnode_check_write_t,
	.mpo_vnode_execve_will_transition =
	    casper_mpo_vnode_execve_will_transition_t,

	/* vnode check */
	// .mpo_vnode_check_lookup = casper_mpo_vnode_check_lookup, // Allow
	// .mpo_vnode_check_readlink = ... // Allow readlink
	.mpo_vnode_check_open =
	    casper_mpo_vnode_check_open, // Can only open restrict files
	.mpo_vnode_check_read = casper_mpo_vnode_check_read_t,	   // Check
	.mpo_vnode_check_stat = casper_mpo_vnode_check_stat_t,	   // Check
	.mpo_vnode_check_create = casper_mpo_vnode_check_create_t, // Check

	/* vnode label */
	// .mpo_vnode_create_extattr = ... // New file don't have label
	.mpo_vnode_init_label = casper_vnode_init_label,
	.mpo_vnode_destroy_label = casper_destroy_label,
	.mpo_vnode_check_relabel = casper_mpo_vnode_check_relabel,
	.mpo_vnode_relabel = casper_mpo_vnode_relabel,
	.mpo_vnode_copy_label = casper_mpo_vnode_copy_label,
	.mpo_vnode_check_setextattr = casper_mpo_vnode_check_setextattr,
	.mpo_vnode_setlabel_extattr = casper_mpo_vnode_setlabel_extattr,
	.mpo_vnode_associate_extattr = casper_mpo_vnode_associate_extattr,
	.mpo_vnode_internalize_label = casper_mpo_vnode_internalize_label,
	.mpo_vnode_externalize_label = casper_mpo_vnode_externalize_label,

	/* cred label */
	// .mpo_cred_check_relabel = ... // Allow relabel
	.mpo_cred_init_label =
	    casper_cred_init_label, // WARNING, do nothing but need implement
	.mpo_cred_destroy_label = casper_destroy_label, // Free the tag memory
	.mpo_cred_relabel = casper_cred_relabel, // Copy tag and allocate memory
	.mpo_cred_internalize_label =
	    casper_mpo_cred_internalize_label, // Resolve tag name and allocate
					       // memory
	.mpo_cred_externalize_label = casper_mpo_cred_externalize_label,
};

/* Register */
MAC_POLICY_SET(&casper_mac_policy_ops, CasperMAC, "Casper MAC policy",
    MPC_LOADTIME_FLAG_UNLOADOK, &casper_slot);
