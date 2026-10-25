#ifndef MAC_CASPER_INTERNAL_H
#define MAC_CASPER_INTERNAL_H

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

#include "../checker.h"
#include "../label.h"
#include "../mac_casper.h"

extern int casper_slot;

int casper_mpo_sysvshm_check_shmget_t(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel, int shmflg);
int casper_mpo_sysvshm_check_shmdt_t(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel);
int casper_mpo_sysvshm_check_shmctl_t(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel, int cmd);
int casper_mpo_sysvshm_check_shmat_t(struct ucred *cred,
    struct shmid_kernel *shmsegptr, struct label *shmseglabel, int shmflg);
int casper_mpo_sysvsem_check_semop_t(struct ucred *cred,
    struct semid_kernel *semakptr, struct label *semaklabel, size_t accesstype);
int casper_mpo_sysvsem_check_semget_t(struct ucred *cred,
    struct semid_kernel *semakptr, struct label *semaklabel);
int casper_mpo_sysvsem_check_semctl_t(struct ucred *cred,
    struct semid_kernel *semakptr, struct label *semaklabel, int cmd);
int casper_mpo_sysvmsq_check_msqsnd_t(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel);
int casper_mpo_sysvmsq_check_msqrcv_t(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel);
int casper_mpo_sysvmsq_check_msqctl_t(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel, int cmd);
int casper_mpo_sysvmsq_check_msqget_t(struct ucred *cred,
    struct msqid_kernel *msqkptr, struct label *msqklabel);
int casper_mpo_sysvmsq_check_msgrmid_t(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel);
int casper_mpo_sysvmsq_check_msgrcv_t(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel);
int casper_mpo_sysvmsq_check_msgmsq_t(struct ucred *cred, struct msg *msgptr,
    struct label *msglabel, struct msqid_kernel *msqkptr,
    struct label *msqklabel);
int casper_mpo_system_check_sysctl_t(struct ucred *cred,
    struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req);
int casper_mpo_system_check_swapoff_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
int casper_mpo_system_check_swapon_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
int casper_mpo_system_check_reboot_t(struct ucred *cred, int howto);
int casper_mpo_system_check_auditon_t(struct ucred *cred, int cmd);
int casper_mpo_system_check_auditctl_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
int casper_mpo_system_check_audit_t(struct ucred *cred, void *record,
    int length);
int casper_mpo_system_check_acct_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
int casper_mpo_proc_check_wait_t(struct ucred *cred, struct proc *proc);
int casper_mpo_proc_check_signal_t(struct ucred *cred, struct proc *proc,
    int signum);
int casper_mpo_proc_check_sched_t(struct ucred *cred, struct proc *p);
int casper_mpo_proc_check_debug_t(struct ucred *cred, struct proc *p);
int casper_mpo_posixshm_check_write_t(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel);
int casper_mpo_posixshm_check_unlink_t(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel);
int casper_mpo_posixshm_check_truncate_t(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel);
int casper_mpo_posixshm_check_stat_t(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel);
int casper_mpo_posixshm_check_setowner_t(struct ucred *cred,
    struct shmfd *shmfd, struct label *shmlabel, uid_t uid, gid_t gid);
int casper_mpo_posixshm_check_setmode_t(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, mode_t mode);
int casper_mpo_posixshm_check_read_t(struct ucred *active_cred,
    struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel);
int casper_mpo_posixshm_check_open_t(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, accmode_t accmode);
int casper_mpo_posixshm_check_mmap_t(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel, int prot, int flags);
int casper_mpo_posixshm_check_create_t(struct ucred *cred, const char *path);
int casper_mpo_posixsem_check_wait_t(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel);
int casper_mpo_posixsem_check_unlink_t(struct ucred *cred, struct ksem *ks,
    struct label *kslabel);
int casper_mpo_posixsem_check_stat_t(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel);
int casper_mpo_posixsem_check_setowner_t(struct ucred *cred, struct ksem *ks,
    struct label *shmlabel, uid_t uid, gid_t gid);
int casper_mpo_posixsem_check_setmode_t(struct ucred *cred, struct ksem *ks,
    struct label *shmlabel, mode_t mode);
int casper_mpo_posixsem_check_post_t(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel);
int casper_mpo_posixsem_check_open_t(struct ucred *cred, struct ksem *ks,
    struct label *kslabel);
int casper_mpo_posixsem_check_getvalue_t(struct ucred *active_cred,
    struct ucred *file_cred, struct ksem *ks, struct label *kslabel);
int casper_mpo_pipe_check_write_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel);
int casper_mpo_pipe_check_stat_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel);
int casper_mpo_pipe_check_relabel_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, struct label *newlabel);
int casper_mpo_pipe_check_read_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel);
int casper_mpo_pipe_check_poll_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel);
int casper_mpo_pipe_check_ioctl_t(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, unsigned long cmd, void *data);
int casper_mpo_mount_check_stat_t(struct ucred *cred, struct mount *mp,
    struct label *mplabel);
int casper_mpo_kld_check_stat_t(struct ucred *cred);
int casper_mpo_kld_check_load_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
int casper_mpo_kenv_check_unset_t(struct ucred *cred, char *name);
int casper_mpo_kenv_check_set_t(struct ucred *cred, char *name, char *value);
int casper_mpo_kenv_check_get_t(struct ucred *cred, char *name);
int casper_mpo_kenv_check_dump_t(struct ucred *cred);
int casper_mpo_ip6_check_jail_t(struct ucred *cred, const struct in6_addr *ia6,
    struct ifnet *ifp);
int casper_mpo_ip4_check_jail_t(struct ucred *cred, const struct in_addr *ia,
    struct ifnet *ifp);
int casper_mpo_inpcb_check_visible_t(struct ucred *cred, struct inpcb *inp,
    struct label *inplabel);
int casper_mpo_ifnet_check_relabel_t(struct ucred *cred, struct ifnet *ifp,
    struct label *ifplabel, struct label *newlabel);
int casper_mpo_cred_check_visible_t(struct ucred *cr1, struct ucred *cr2);
int casper_mpo_cred_check_setuid_t(struct ucred *cred, uid_t uid);
int casper_mpo_cred_check_setreuid_t(struct ucred *cred, uid_t ruid,
    uid_t euid);
int casper_mpo_cred_check_setresuid_t(struct ucred *cred, uid_t ruid,
    uid_t euid, uid_t suid);
int casper_mpo_cred_check_setresgid_t(struct ucred *cred, gid_t rgid,
    gid_t egid, gid_t sgid);
int casper_mpo_cred_check_setregid_t(struct ucred *cred, gid_t rgid,
    gid_t egid);
int casper_mpo_cred_check_setgroups_t(struct ucred *cred, int ngroups,
    gid_t *gidset);
int casper_po_cred_check_setgid_t(struct ucred *cred, gid_t gid);
int casper_mpo_cred_check_seteuid_t(struct ucred *cred, uid_t euid);
int casper_mpo_cred_check_setegid_t(struct ucred *cred, gid_t egid);
int casper_mpo_cred_check_setcred_t(u_int flags, const struct ucred *old_cred,
    struct ucred *new_cred);
int casper_mpo_cred_check_setauid_t(struct ucred *cred, uid_t auid);
int casper_mpo_cred_check_setaudit_addr_t(struct ucred *cred,
    struct auditinfo_addr *aia);
int casper_mpo_cred_check_setaudit_t(struct ucred *cred, struct auditinfo *ai);
int casper_deny_default(const struct ucred *cred);
struct mac_casper *casper_get_label(const struct ucred *cred);
int casper_mpo_socket_check_visible_t(struct ucred *cred, struct socket *so,
    struct label *solabel);
int casper_mpo_socket_check_stat_t(struct ucred *cred, struct socket *so,
    struct label *solabel);
int casper_mpo_socket_check_send_t(struct ucred *cred, struct socket *so,
    struct label *solabel);
int casper_mpo_socket_check_relabel_t(struct ucred *cred, struct socket *so,
    struct label *solabel, struct label *newlabel);
int casper_mpo_socket_check_receive_t(struct ucred *cred, struct socket *so,
    struct label *solabel);
int casper_mpo_socket_check_poll_t(struct ucred *cred, struct socket *so,
    struct label *solabel);
int casper_mpo_socket_check_listen_t(struct ucred *cred, struct socket *so,
    struct label *solabel);
int casper_mpo_socket_check_create_t(struct ucred *cred, int domain, int type,
    int protocol);
int casper_mpo_socket_check_connect_t(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa);
int casper_mpo_socket_check_bind_t(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa);
int casper_mpo_socket_check_accept_t(struct ucred *cred, struct socket *so,
    struct label *solabel);
int casper_mpo_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct componentname *cnp);
int casper_mpo_vnode_check_stat_t(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel);
int casper_mpo_vnode_check_read_t(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel);
int casper_mpo_vnode_check_create_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp, struct vattr *vap);
int casper_mpo_vnode_check_open(struct ucred *cred, struct vnode *vp,
    struct label *label, int acc_mode);
int casper_mpo_vnode_execve_will_transition_t(struct ucred *old,
    struct vnode *vp, struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel);
int casper_mpo_vnode_check_write_t(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel);
int casper_mpo_vnode_check_unlink_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp);
int casper_mpo_vnode_check_setutimes_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct timespec atime, struct timespec mtime);
int casper_mpo_vnode_check_setowner_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, uid_t uid, gid_t gid);
int casper_mpo_vnode_check_setmode_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, mode_t mode);
int casper_mpo_vnode_check_setflags_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, u_long flags);
int casper_mpo_vnode_check_setacl_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type, struct acl *acl);
int casper_mpo_vnode_check_revoke_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel);
int casper_mpo_vnode_check_rename_to_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    int samedir, struct componentname *cnp);
int casper_mpo_vnode_check_rename_from_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp);
int casper_mpo_vnode_check_readdir_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel);
int casper_mpo_vnode_check_poll_t(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel);
int casper_mpo_vnode_check_mprotect_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot);
int casper_mpo_vnode_check_mmap_t(struct ucred *cred, struct vnode *vp,
    struct label *label, int prot, int flags);
int casper_mpo_vnode_check_listextattr_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace);
int casper_mpo_vnode_check_link_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp);
int casper_mpo_vnode_check_getextattr_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name);
int casper_mpo_vnode_check_getacl_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type);
int casper_mpo_vnode_check_exec_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp, struct label *execlabel);
int casper_mpo_vnode_check_deleteextattr_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name);
int casper_mpo_vnode_check_deleteacl_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type);
int casper_mpo_vnode_check_chroot_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel);
int casper_mpo_vnode_check_chdir_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel);
int casper_mpo_vnode_check_access_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode);
int casper_mpo_cred_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed);
int casper_mpo_cred_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed);
void casper_cred_relabel(struct ucred *cred, struct label *newlabel);
void casper_cred_init_label(struct label *label);
int casper_mpo_vnode_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed);
int casper_mpo_vnode_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed);
int casper_mpo_vnode_associate_extattr(struct mount *mp, struct label *mplabel,
    struct vnode *vp, struct label *vplabel);
int casper_mpo_vnode_setlabel_extattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *intlabel);
int casper_mpo_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name);
void casper_mpo_vnode_copy_label(struct label *src, struct label *dest);
void casper_mpo_vnode_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *label);
int casper_mpo_vnode_check_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel);
void casper_vnode_init_label(struct label *label);
void casper_destroy_label(struct label *label);
void casper_destroy(struct mac_policy_conf *mpc);
void casper_init(struct mac_policy_conf *conf);

#endif /* MAC_CASPER_INTERNAL_H */
