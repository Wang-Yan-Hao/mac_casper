#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/mac.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/socket.h> // For sockaddr (generic)
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/uma.h>

#include <netinet/in.h>	 // For sockaddr_in (IPv4)
#include <netinet/ip6.h> // For sockaddr_in6 (IPv6)

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>
#include <security/mac/mac_syscalls.h>

#include "mac_policy_ops.h"

static int casper_slot;
static uma_zone_t zone_casper;

/* Helper function */
static inline struct mac_casper *
casper_get_label(struct ucred *cred)
{
    if (cred == NULL || cred->cr_label == NULL)
        return NULL;

    struct mac_casper *label = SLOT(cred->cr_label);
    return label;
}

static int
casper_deny_default(const struct ucred *cred)
{
	if (cred == NULL || cred->cr_label == NULL)
		return 0;

	struct mac_casper *obj = SLOT(cred->cr_label);
	if (obj == NULL || obj->label[0] == '\0')
		return 0;

	for (int i = 0; casper_blocked_labels[i] != NULL; i++) {
		if (!strcmp(obj->label, casper_blocked_labels[i]))
			return EACCES;
	}
	return 0;
}

/* Funciton Implement Checker */
/* bpfdsec */
/* cred */
static void
casper_cred_relabel(struct ucred *cred, struct label *newlabel)
{
	struct mac_casper *source, *dest;

	if (cred == NULL || newlabel == NULL)
		return;

	source = SLOT(newlabel);
	if (source == NULL)
		return;

	dest = SLOT(cred->cr_label);
	if (dest == NULL) {
		// Use M_NOWAIT to prevent sleeping inside a non-sleepable lock
		dest = uma_zalloc(zone_casper, M_NOWAIT);
		if (dest == NULL) {
			return;
		}

		bzero(dest, sizeof(*dest)); // Ensure zero-initialization
		SLOT_SET(cred->cr_label, dest);
		*dest = *source;
	}
}
static void
casper_cred_destroy_label(struct label *label)
{
	struct mac_casper *cur = SLOT(label);
	if (cur != NULL)
		uma_zfree(zone_casper, cur);
	SLOT_SET(label, NULL);
}
static int
casper_mpo_cred_internalize_label_t(struct label *label, char *element_name,
    char *element_data, int *claimed)
{
	// printf("casper_mpo_cred_internalize_label_t start\n");
	// printf("element_name: %s\n", element_name);
	// printf("element_data: %s\n", element_data);

	struct mac_casper *memory;

	if (strcmp(MAC_CASPER_LABEL_NAME, element_name) != 0)
		return 0;

	memory = uma_zalloc(zone_casper, M_NOWAIT);
	if (memory == NULL) {
		return ENOMEM;
	}

	// Initialize the entire structure to zero (safe default)
	memset(memory, 0, sizeof(struct mac_casper));

	// Safely copy the label from element_data (ensure null termination)
	if (element_data != NULL) {
		strlcpy(memory->label, element_data, sizeof(memory->label));
	}

	// Ensure original_filename is an empty string
	memory->original_filename[0] = '\0';

	// Mark that the label was claimed
	(*claimed)++;

	// Set the allocated memory into the slot
	SLOT_SET(label, memory);

	// printf("casper_mpo_cred_internalize_label_t finish\n");
	return 0;
}
static int
casper_mpo_cred_check_relabel_t(struct ucred *cred, struct label *newlabel)
{
	return casper_deny_default(cred);
}
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
/* priv */
static int
casper_mpo_priv_check_t(struct ucred *cred, int priv)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_priv_grant_t(struct ucred *cred, int priv)
{
	return casper_deny_default(cred);
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
	if (cred == NULL || cred->cr_label == NULL)
		return 0;
	struct mac_casper *obj = SLOT(cred->cr_label);
	if (obj == NULL)
		return 0;

	if (!strcmp(obj->label, "dns")) {
		// printf("casper_mpo_socket_check_connect_t\n");

		/* Flag */
		bool ipv4 = true;
		bool pass = false;
		char ip_str[INET_ADDRSTRLEN]; // Allocate buffer for the IP
					      // address string
		// struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;

		// Check if sockaddr is IPv4 or IPv6
		if (sa->sa_family == AF_INET) {
			inet_ntoa_r(sin->sin_addr,
			    ip_str); // Convert the raw address to a string
				     // printf("Connecting to IP (IPv4): %s\n",
			// ip_str); // Print the IP address as a string
		} else if (sa->sa_family == AF_INET6) {
			ipv4 = false;

			// printf("Connecting to IP (IPv6): ");
			// for (int i = 0; i < 16; i++) {
			// printf("%02x",
			// sin6->sin6_addr
			// .s6_addr[i]); // Print raw IPv6 address
			//   in hex
			// if (i < 15) {
			// printf(":");
			// }
			// }
			// printf("\n");
		}

		struct nameidata nd;
		struct vnode *vp;
		struct uio auio;
		struct iovec aiov;
		char *buf;
		int error;
		off_t offset = 0;
		size_t bytes_read;
		int nserv = 0;

		// Allocate buffer in kernel space
		buf = (char *)malloc(BUF_SIZE, M_TEMP, M_WAITOK | M_ZERO);
		if (!buf) {
			// printf("[Kernel] Failed to allocate buffer\n");
			return 0;
		}

		NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, "/etc/resolv.conf");

		error = namei(&nd);
		if (error) {
			// printf("[Kernel] namei() failed: %d\n", error);
			free(buf, M_TEMP);
			return 0;
		}

		vp = nd.ni_vp;

		if (vp->v_type != VREG) {
			// printf(
			// "[Kernel] /etc/resolv.conf is not a regular file\n");
			vrele(vp);
			free(buf, M_TEMP);
			return 0;
		}

		// Read file contents
		// printf("[Kernel] Reading /etc/resolv.conf...\n");

		while (nserv < MAX_NAMESERVERS) {
			aiov.iov_base = buf;
			aiov.iov_len = BUF_SIZE;
			auio.uio_iov = &aiov;
			auio.uio_iovcnt = 1;
			auio.uio_offset = offset;
			auio.uio_resid = BUF_SIZE;
			auio.uio_segflg = UIO_SYSSPACE;
			auio.uio_rw = UIO_READ;
			auio.uio_td = curthread; // Current kernel thread

			// error = vn_rdwr(UIO_READ, vp, buf, BUF_SIZE, offset,
			// UIO_SYSSPACE,
			//                 IO_NODELOCKED, curthread->td_ucred,
			//                 curthread->td_ucred, NULL,
			//                 curthread);

			error = VOP_READ(vp, &auio, IO_NODELOCKED,
			    curthread->td_ucred);

			if (error) {
				// printf("[Kernel] vnode type: %d\n",
				// vp->v_type); printf("[Kernel] vnode path:
				// %s\n",
				//     nd.ni_cnd.cn_nameptr);
				// printf("[Kernel] Mount flags: 0x%lx\n",
				//     vp->v_mount->mnt_flag);

				// printf("[Kernel] auio.uio_resid %zd\n",
				//     auio.uio_resid);
				// printf("[Kernel] error number: %d\n", error);
				// printf("[Kernel] Error in vn_rdwr\n");
				// printf("[Kernel] vnode type: %d\n",
				// vp->v_type);
				return 0;
			}

			if (auio.uio_resid == BUF_SIZE) {
				break; // End of file
			}

			bytes_read = BUF_SIZE - auio.uio_resid;
			offset += bytes_read;

			// Parse buffer for "nameserver" entries
			char *line = buf;
			while ((line = strsep(&buf, "\n")) != NULL) {
				// printf("[Kernel] Line %s\n", line);
				if (strncmp(line, "nameserver", 10) == 0) {
					char *cp = line + 10;

					// Skip spaces
					while (*cp == ' ' || *cp == '\t')
						cp++;

					if (*cp) { // If IP is present
						// printf(
						//     "[Kernel] Found
						//     nameserver: %s\n", cp);

						if (ipv4) {
							// printf("[IP] %s\n",
							//     ip_str);
							if (!strncmp(cp, ip_str,
								strlen(
								    ip_str))) { // Fixed typo & logic
								pass = true;
							}
						}
						// else {} TODO
						nserv++;
					}
				}
			}
		}

		if (pass) {
			// printf("[Pass]\n");
		} else {
			return (EACCES);
		}

		// Cleanup
		vrele(vp);
		free(buf, M_TEMP);
	} else if (!strcmp(obj->label, "fileargs")) {
		return (EACCES);
	} else if (!strcmp(obj->label, "grp")) {
		return (EACCES);
	}

	return 0;
}
static int
casper_mpo_socket_check_create_t(struct ucred *cred, int domain, int type,
    int protocol)
{
	struct mac_casper *obj = casper_get_label(cred);
	if (obj== NULL)
		return 0;

	if(!strcmp(obj->label, "dns")) {
		return 0;
	} else if (!strcmp (obj->label, "fileargs")) {
		return (EACCES);
	}  else if (!strcmp (obj->label, "grp")) {
		return (EACCES);
	}

	return 0;
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
	return casper_deny_default(cred);
}
static int
casper_mpo_socket_check_receive_t(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct mac_casper *obj = casper_get_label(cred);
	if (obj== NULL)
		return 0;

	if(!strcmp(obj->label, "dns")) {
		return 0;
	} else if (!strcmp (obj->label, "fileargs")) {
		return (EACCES);
	}  else if (!strcmp (obj->label, "grp")) {
		return (EACCES);
	}

	return casper_deny_default(cred);
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
	return casper_deny_default(cred);
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
	return casper_deny_default(cred);
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
casper_mpo_vnode_check_create_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp, struct vattr *vap)
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
casper_mpo_vnode_check_lookup_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp)
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
casper_mpo_vnode_check_open(struct ucred *cred, struct vnode *vp,
    struct label *label, int acc_mode)
{
	// printf("casper_mpo_vnode_check_open start\n");
	char *filename = NULL, *freebuf = NULL;
	int error;

	struct mac_casper *obj = casper_get_label(cred);
	if (obj == NULL) {
		return 0;
	}
	// printf("casper_mpo_vnode_check_open: obj != NULL\n");
	// printf("casper_mpo_vnode_check_open: label %s\n", obj->label);

	// Check for the specific label "dns"
	if (!strcmp(obj->label, "dns")) {
		// Check soft link original_filename
		for (int i = 0; casper_dns_allowed_files_open[i] != NULL; i++) {
			if (!strcmp(obj->original_filename,
				casper_dns_allowed_files_open[i])) {
				obj->original_filename[0] = '\0';
				return 0;
			}
		}

		// Get the full path of the vnode
		error = vn_fullpath(vp, &filename, &freebuf);
		// If full path retrieval fails, allow access (fail-safe policy)
		if (error != 0 || filename == NULL) {
			return 0;
		}

		// Restrict access to specific paths
		int allowed = 0; // Flag to track if the filename is allowed
		for (int i = 0; casper_dns_allowed_files_open[i] != NULL; i++) {
			if (strcmp(filename,
				casper_dns_allowed_files_open[i]) == 0) {
				allowed = 1;
				break;
			}
		}

		if (!allowed) {
			free(freebuf, M_TEMP); // Free allocated buffer
			return (EACCES);       // Deny access
		}

		// Free allocated buffer after successful checks
		free(freebuf, M_TEMP);
	} else if (!strcmp(obj->label, "fileargs")) {
		return 0;
	} else if (!strcmp((obj->label), "grp")) {
		for (int i = 0; grp_allowed_files_open[i] != NULL; i++) {
			if (!strcmp(obj->original_filename,
				grp_allowed_files_open[i])) {
				obj->original_filename[0] = '\0';
				return 0;
			}
		}

		error = vn_fullpath(vp, &filename, &freebuf);
		if (error != 0 || filename == NULL) {
			return 0;
		}

		int allowed = 0;
		for (int i = 0; grp_allowed_files_open[i] != NULL; i++) {
			if (strcmp(filename,
				grp_allowed_files_open[i]) == 0) {
				allowed = 1;
				break;
			}
		}

		if (!allowed) {
			free(freebuf, M_TEMP);
			return (EACCES);
		}

		free(freebuf, M_TEMP);
		return 0;
	}

	return 0; // Allow access for other labels or conditions
}
static int
casper_mpo_vnode_check_poll_t(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel)
{
	return casper_deny_default(active_cred);
}
static int
casper_mpo_vnode_check_read_t(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel)
{
	return 0; // Allow other access
}
static int
casper_mpo_vnode_check_readdir_t(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_check_readlink_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	char *filename = NULL, *freebuf = NULL;
	int error;

	if (cred == NULL || cred->cr_label == NULL) {
		return 0;
	}

	struct mac_casper *obj = SLOT(cred->cr_label);
	if (obj == NULL) {
		return 0;
	}

	// Check for the specific label "dns"
	if (!strcmp(obj->label, "dns")) {
		for (int i = 0; casper_dns_allowed_files_open[i] != NULL; i++) {
			if (!strcmp(obj->original_filename,
				casper_dns_allowed_files_open[i])) {
				obj->original_filename[0] = '\0';
				return 0;
			}
		}

		// Get the full path of the vnode
		error = vn_fullpath(vp, &filename, &freebuf);

		// If full path retrieval fails, allow access (fail-safe policy)
		if (error != 0 || filename == NULL) {
			return 0;
		}

		// Restrict access to specific paths
		int allowed = 0; // Flag to track if the filename is allowed
		for (int i = 0; casper_dns_allowed_files_open[i] != NULL; i++) {
			if (strcmp(filename,
				casper_dns_allowed_files_open[i]) == 0) {
				allowed = 1;
				break;
			}
		}

		if (!allowed) {
			free(freebuf, M_TEMP); // Free allocated buffer
			return (EACCES);       // Deny access
		}

		strlcpy(obj->original_filename, filename,
		    sizeof(obj->original_filename));

		// Free allocated buffer after successful checks
		free(freebuf, M_TEMP);
	}

	return 0; // Allow access for other labels or conditions
}
static int
casper_mpo_vnode_check_relabel_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel)
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
casper_mpo_vnode_check_setextattr_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
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
casper_mpo_vnode_check_stat_t(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *vplabel)
{
	struct mac_casper *obj = casper_get_label(active_cred);
	if (obj == NULL)
		return 0;

	if (!strcmp(obj->label, "dns")) {
		return (EACCES);
	} else if (!strcmp(obj->label, "fileargs")) {
		return 0;
	} else if (!strcmp(obj->label, "grp")) {
		return (EACCES);
	}

	return 0;
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
casper_mpo_vnode_create_extattr_t(struct ucred *cred, struct mount *mp,
    struct label *mplabel, struct vnode *dvp, struct label *dvplabel,
    struct vnode *vp, struct label *vplabel, struct componentname *cnp)
{
	return casper_deny_default(cred);
}
static int
casper_mpo_vnode_execve_will_transition_t(struct ucred *old, struct vnode *vp,
    struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel)
{
	return casper_deny_default(old);
}
static int
casper_mpo_vnode_setlabel_extattr_t(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *intlabel)
{
	return casper_deny_default(cred);
}
/* init */
static void
casper_init(struct mac_policy_conf *conf)
{
	/* Check if zone_casper is already created */
	zone_casper = uma_zcreate("mac_casper", sizeof(struct mac_casper), NULL,
	    NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
	if (zone_casper == NULL) {
		// printf("Failed to create uma zone for casper\n");
		return;
	}
}
static void
casper_destroy(struct mac_policy_conf *mpc)
{
	if (zone_casper != NULL) {
		uma_zdestroy(zone_casper);
		zone_casper = NULL;
	}
}

static void
casper_cred_init_label(struct label *label)
{
	// printf("casper_cred_init_label\n");
	return;
}

/* Base structure */
static struct mac_policy_ops caspe_mac_policy_ops = {
	/* init */
	.mpo_init = casper_init,       // Enable
	.mpo_destroy = casper_destroy, // Enable
	/* bpfdsec */
	/* cred */
	// .mpo_cred_check_relabel = ... // Allow relabel
	.mpo_cred_init_label = casper_cred_init_label,
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
	.mpo_cred_destroy_label =
	    casper_cred_destroy_label, // Free the tag memory
	.mpo_cred_internalize_label =
	    casper_mpo_cred_internalize_label_t, // Give tag name
	.mpo_cred_relabel = casper_cred_relabel, // Enable and malloc memory
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
	/* priv */
	.mpo_priv_check = casper_mpo_priv_check_t,
	.mpo_priv_grant = casper_mpo_priv_grant_t,
	/* proc */
	.mpo_proc_check_debug = casper_mpo_proc_check_debug_t,
	.mpo_proc_check_sched = casper_mpo_proc_check_sched_t,
	.mpo_proc_check_signal = casper_mpo_proc_check_signal_t,
	.mpo_proc_check_wait = casper_mpo_proc_check_wait_t,
	/* socket */
	.mpo_socket_check_accept = casper_mpo_socket_check_accept_t,
	.mpo_socket_check_bind = casper_mpo_socket_check_bind_t,
	.mpo_socket_check_connect =
	    casper_mpo_socket_check_connect_t, // Check
	.mpo_socket_check_create = casper_mpo_socket_check_create_t, //
	// Enable
	.mpo_socket_check_listen = casper_mpo_socket_check_listen_t,
	// .mpo_socket_check_poll = casper_mpo_socket_check_poll_t, // Casper Enable
	// .mpo_socket_check_receive = casper_mpo_socket_check_receive_t, // Casper Enable
	.mpo_socket_check_relabel = casper_mpo_socket_check_relabel_t,
	// .mpo_socket_check_send = casper_mpo_socket_check_send_t, // Casper Enable
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
	/* vnode */
	.mpo_vnode_check_access = casper_mpo_vnode_check_access_t,
	.mpo_vnode_check_chdir = casper_mpo_vnode_check_chdir_t,
	.mpo_vnode_check_chroot = casper_mpo_vnode_check_chroot_t,
	.mpo_vnode_check_create = casper_mpo_vnode_check_create_t,
	.mpo_vnode_check_deleteacl = casper_mpo_vnode_check_deleteacl_t,
	.mpo_vnode_check_deleteextattr = casper_mpo_vnode_check_deleteextattr_t,
	.mpo_vnode_check_exec = casper_mpo_vnode_check_exec_t,
	.mpo_vnode_check_getacl = casper_mpo_vnode_check_getacl_t,
	.mpo_vnode_check_getextattr = casper_mpo_vnode_check_getextattr_t,
	.mpo_vnode_check_link = casper_mpo_vnode_check_link_t,
	.mpo_vnode_check_listextattr = casper_mpo_vnode_check_listextattr_t,
	// .mpo_vnode_check_lookup = casper_mpo_vnode_check_lookup_t, // Enable
	.mpo_vnode_check_mmap = casper_mpo_vnode_check_mmap_t,
	.mpo_vnode_check_mprotect = casper_mpo_vnode_check_mprotect_t,
	.mpo_vnode_check_open =
	    casper_mpo_vnode_check_open, // Can only open restrict files
	.mpo_vnode_check_poll = casper_mpo_vnode_check_poll_t,
	// .mpo_vnode_check_read = casper_mpo_vnode_check_read_t, // Enable
	.mpo_vnode_check_readdir = casper_mpo_vnode_check_readdir_t,
	.mpo_vnode_check_readlink = casper_mpo_vnode_check_readlink_t, // DNS softlink
	.mpo_vnode_check_relabel = casper_mpo_vnode_check_relabel_t,
	.mpo_vnode_check_rename_from = casper_mpo_vnode_check_rename_from_t,
	.mpo_vnode_check_rename_to = casper_mpo_vnode_check_rename_to_t,
	.mpo_vnode_check_revoke = casper_mpo_vnode_check_revoke_t,
	.mpo_vnode_check_setacl = casper_mpo_vnode_check_setacl_t,
	.mpo_vnode_check_setextattr = casper_mpo_vnode_check_setextattr_t,
	.mpo_vnode_check_setflags = casper_mpo_vnode_check_setflags_t,
	.mpo_vnode_check_setmode = casper_mpo_vnode_check_setmode_t,
	.mpo_vnode_check_setowner = casper_mpo_vnode_check_setowner_t,
	.mpo_vnode_check_setutimes = casper_mpo_vnode_check_setutimes_t,
	.mpo_vnode_check_stat = casper_mpo_vnode_check_stat_t,
	.mpo_vnode_check_unlink = casper_mpo_vnode_check_unlink_t,
	.mpo_vnode_check_write = casper_mpo_vnode_check_write_t,
	.mpo_vnode_create_extattr = casper_mpo_vnode_create_extattr_t,
	.mpo_vnode_execve_will_transition =
	    casper_mpo_vnode_execve_will_transition_t,
	.mpo_vnode_setlabel_extattr = casper_mpo_vnode_setlabel_extattr_t,
};

/* Register */
MAC_POLICY_SET(&caspe_mac_policy_ops, CaspeMAC, "Caspe MAC policy",
    MPC_LOADTIME_FLAG_UNLOADOK, &casper_slot);
