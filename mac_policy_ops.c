#include <sys/param.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/mac.h>

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>
#include <security/mac/mac_syscalls.h>

#include <vm/uma.h>
#include <vm/vm.h>

/* My label */
struct mac_casper {
    char label[20];
    char original_filename[40];
};

static int casper_slot;
/* UMA */
static uma_zone_t zone_casper;
const char *casper_label = "casper";

#define SLOT(l) ((struct mac_casper *)mac_label_get((l), casper_slot))
#define SLOT_SET(l, val) mac_label_set((l), casper_slot, (uintptr_t)(val))

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
    }

    *dest = *source;
}
static void
casper_cred_destroy_label(struct label *label) {
    struct mac_casper *cur = SLOT(label);
    if (cur != NULL)
        uma_zfree(zone_casper, cur);
    SLOT_SET(label, NULL);
}
static int
casper_mpo_cred_internalize_label_t(struct label *label, char *element_name, char *element_data, int *claimed) {
    struct mac_casper *memory;

    if (strcmp(casper_label, element_name) != 0)
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
    return 0;
}
static int
casper_mpo_cred_check_relabel_t (struct ucred *cred, struct label *newlabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_cred_check_setaudit_t (struct ucred *cred, struct auditinfo *ai) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_cred_check_setaudit_addr_t (struct ucred *cred, struct auditinfo_addr *aia) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_cred_check_setauid_t (struct ucred *cred, uid_t auid) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

static int
casper_mpo_cred_check_setcred_t (u_int flags, const struct ucred *old_cred, struct ucred *new_cred) {
    if (old_cred == NULL || old_cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(old_cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_cred_check_setegid_t (struct ucred *cred, gid_t egid) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_cred_check_seteuid_t (struct ucred *cred, uid_t euid) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_po_cred_check_setgid_t (struct ucred *cred, gid_t gid) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_cred_check_setgroups_t (struct ucred *cred, int ngroups, gid_t *gidset) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_cred_check_setregid_t (struct ucred *cred, gid_t rgid, gid_t egid) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_cred_check_setresgid_t (struct ucred *cred, gid_t rgid, gid_t egid, gid_t sgid) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_cred_check_setresuid_t (struct ucred *cred, uid_t ruid, uid_t euid, uid_t suid) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_cred_check_setreuid_t (struct ucred *cred, uid_t ruid, uid_t euid) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_cred_check_setuid_t (struct ucred *cred, uid_t uid) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_cred_check_visible_t (struct ucred *cr1, struct ucred *cr2) {
    if (cr1 == NULL || cr1->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cr1->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* ddb */
/* devfs */

/* ifnet */
static int
casper_mpo_ifnet_check_relabel_t (struct ucred *cred, struct ifnet *ifp, struct label *ifplabel, struct label *newlabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* inpcb */
static int
casper_mpo_inpcb_check_visible_t (struct ucred *cred, struct inpcb *inp, struct label *inplabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* ip6q */
/* jail */
static int
casper_mpo_ip4_check_jail_t (struct ucred *cred, const struct in_addr *ia, struct ifnet *ifp) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_ip6_check_jail_t(struct ucred *cred, const struct in6_addr *ia6, struct ifnet *ifp) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
/* ipq */
/* kdb */

/* kenv */
static int
casper_mpo_kenv_check_dump_t (struct ucred *cred) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_kenv_check_get_t (struct ucred *cred, char *name) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_kenv_check_set_t (struct ucred *cred, char *name, char *value) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_kenv_check_unset_t (struct ucred *cred, char *name) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* kld */
static int
casper_mpo_kld_check_load_t (struct ucred *cred, struct vnode *vp, struct label *vplabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_kld_check_stat_t (struct ucred *cred) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* mbuf */

/* mount */
static int
casper_mpo_mount_check_stat_t (struct ucred *cred, struct mount *mp, struct label *mplabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* netinet */
/* netinet6 */

/* pipe */
static int
casper_mpo_pipe_check_ioctl_t (struct ucred *cred, struct pipepair *pp, struct label *pplabel, unsigned long cmd, void *data) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_pipe_check_poll_t (struct ucred *cred, struct pipepair *pp, struct label *pplabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_pipe_check_read_t (struct ucred *cred, struct pipepair *pp, struct label *pplabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_pipe_check_relabel_t (struct ucred *cred, struct pipepair *pp, struct label *pplabel, struct label *newlabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_pipe_check_stat_t (struct ucred *cred, struct pipepair *pp, struct label *pplabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_pipe_check_write_t (struct ucred *cred, struct pipepair *pp, struct label *pplabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* posixsem */
static int
casper_mpo_posixsem_check_getvalue_t (struct ucred *active_cred, struct ucred *file_cred, struct ksem *ks, struct label *kslabel) {
    if (active_cred == NULL || active_cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(active_cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixsem_check_open_t (struct ucred *cred, struct ksem *ks, struct label *kslabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixsem_check_post_t (struct ucred *active_cred, struct ucred *file_cred, struct ksem *ks, struct label *kslabel) {
    if (active_cred == NULL || active_cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(active_cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixsem_check_setmode_t (struct ucred *cred, struct ksem *ks, struct label *shmlabel, mode_t mode) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixsem_check_setowner_t (struct ucred *cred, struct ksem *ks, struct label *shmlabel, uid_t uid, gid_t gid) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixsem_check_stat_t (struct ucred *active_cred, struct ucred *file_cred, struct ksem *ks, struct label *kslabel) {
    if (active_cred == NULL || active_cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(active_cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixsem_check_unlink_t (struct ucred *cred, struct ksem *ks, struct label *kslabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixsem_check_wait_t (struct ucred *active_cred, struct ucred *file_cred, struct ksem *ks, struct label *kslabel) {
    if (active_cred == NULL || active_cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(active_cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* posixshm */
static int
casper_mpo_posixshm_check_create_t (struct ucred *cred, const char *path) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixshm_check_mmap_t (struct ucred *cred, struct shmfd *shmfd, struct label *shmlabel, int prot, int flags) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixshm_check_open_t (struct ucred *cred, struct shmfd *shmfd, struct label *shmlabel, accmode_t accmode) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixshm_check_read_t (struct ucred *active_cred, struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel) {
    if (active_cred == NULL || active_cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(active_cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixshm_check_setmode_t (struct ucred *cred, struct shmfd *shmfd, struct label *shmlabel, mode_t mode) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixshm_check_setowner_t (struct ucred *cred, struct shmfd *shmfd, struct label *shmlabel, uid_t uid, gid_t gid) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixshm_check_stat_t (struct ucred *active_cred, struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel) {
    if (active_cred == NULL || active_cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(active_cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixshm_check_truncate_t (struct ucred *active_cred, struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel) {
    if (active_cred == NULL || active_cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(active_cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixshm_check_unlink_t (struct ucred *cred, struct shmfd *shmfd, struct label *shmlabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_posixshm_check_write_t (struct ucred *active_cred, struct ucred *file_cred, struct shmfd *shmfd, struct label *shmlabel) {
    if (active_cred == NULL || active_cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(active_cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* priv */
static int
casper_mpo_priv_check_t (struct ucred *cred, int priv) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_priv_grant_t (struct ucred *cred, int priv) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* proc */
static int
casper_mpo_proc_check_debug_t (struct ucred *cred, struct proc *p) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_proc_check_sched_t (struct ucred *cred, struct proc *p) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_proc_check_signal_t (struct ucred *cred, struct proc *proc, int signum) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_proc_check_wait_t (struct ucred *cred, struct proc *proc) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* socket */
static int
casper_mpo_socket_check_accept_t (struct ucred *cred, struct socket *so, struct label *solabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_socket_check_bind_t (struct ucred *cred, struct socket *so, struct label *solabel, struct sockaddr *sa) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
#include <netinet/in.h>  // For sockaddr_in (IPv4)
#include <netinet/ip6.h> // For sockaddr_in6 (IPv6)
#include <sys/socket.h>  // For sockaddr (generic)


static int
casper_mpo_socket_check_connect_t (struct ucred *cred, struct socket *so, struct label *solabel, struct sockaddr *sa) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;

    if (!strcmp(obj->label, "dns")) {
        printf("casper_mpo_socket_check_connect_t\n");

        // Check if sockaddr is IPv4 or IPv6
        if (sa->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)sa;
            char ip_str[INET_ADDRSTRLEN];  // Allocate buffer for the IP address string
            inet_ntoa_r(sin->sin_addr, ip_str);  // Convert the raw address to a string
            printf("Connecting to IP (IPv4): %s\n", ip_str);  // Print the IP address as a string
        }
        else if (sa->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
            printf("Connecting to IP (IPv6): ");
            for (int i = 0; i < 16; i++) {
                printf("%02x", sin6->sin6_addr.s6_addr[i]); // Print raw IPv6 address in hex
                if (i < 15) {
                    printf(":");
                }
            }
            printf("\n");
        }
        return 0;
    }

    return 0;
}
static int
casper_mpo_socket_check_create_t (struct ucred *cred, int domain, int type, int protocol) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_socket_check_listen_t (struct ucred *cred, struct socket *so, struct label *solabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_socket_check_poll_t (struct ucred *cred, struct socket *so, struct label *solabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_socket_check_receive_t (struct ucred *cred, struct socket *so, struct label *solabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_socket_check_relabel_t (struct ucred *cred, struct socket *so, struct label *solabel, struct label *newlabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_socket_check_send_t (struct ucred *cred, struct socket *so, struct label *solabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;

    if (!strcmp(obj->label, "dns")) {
        printf("casper_mpo_socket_check_send_t\n");

        return 0;
    }
    return 0;
}
static int
casper_mpo_socket_check_stat_t (struct ucred *cred, struct socket *so, struct label *solabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_socket_check_visible_t (struct ucred *cred, struct socket *so, struct label *solabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* socketpeer */
/* syncache */

/* system */
static int
casper_mpo_system_check_acct_t (struct ucred *cred, struct vnode *vp, struct label *vplabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_system_check_audit_t (struct ucred *cred, void *record, int length) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_system_check_auditctl_t (struct ucred *cred, struct vnode *vp, struct label *vplabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_system_check_auditon_t (struct ucred *cred, int cmd) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_system_check_reboot_t (struct ucred *cred, int howto) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_system_check_swapon_t (struct ucred *cred, struct vnode *vp, struct label *vplabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_system_check_swapoff_t (struct ucred *cred, struct vnode *vp, struct label *vplabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_system_check_sysctl_t (struct ucred *cred, struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* sysvmsg */

/* sysvmsq */
static int
casper_mpo_sysvmsq_check_msgmsq_t (struct ucred *cred, struct msg *msgptr, struct label *msglabel, struct msqid_kernel *msqkptr, struct label *msqklabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_sysvmsq_check_msgrcv_t (struct ucred *cred, struct msg *msgptr, struct label *msglabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_sysvmsq_check_msgrmid_t (struct ucred *cred, struct msg *msgptr, struct label *msglabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_sysvmsq_check_msqget_t (struct ucred *cred, struct msqid_kernel *msqkptr, struct label *msqklabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_sysvmsq_check_msqctl_t (struct ucred *cred, struct msqid_kernel *msqkptr, struct label *msqklabel, int cmd) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_sysvmsq_check_msqrcv_t (struct ucred *cred, struct msqid_kernel *msqkptr, struct label *msqklabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_sysvmsq_check_msqsnd_t (struct ucred *cred, struct msqid_kernel *msqkptr, struct label *msqklabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* sysvsem */
static int
casper_mpo_sysvsem_check_semctl_t (struct ucred *cred, struct semid_kernel *semakptr, struct label *semaklabel, int cmd) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_sysvsem_check_semget_t (struct ucred *cred, struct semid_kernel *semakptr, struct label *semaklabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_sysvsem_check_semop_t (struct ucred *cred, struct semid_kernel *semakptr, struct label *semaklabel, size_t accesstype) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* sysvshm */
static int
casper_mpo_sysvshm_check_shmat_t (struct ucred *cred, struct shmid_kernel *shmsegptr, struct label *shmseglabel, int shmflg) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_sysvshm_check_shmctl_t (struct ucred *cred, struct shmid_kernel *shmsegptr, struct label *shmseglabel, int cmd) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_sysvshm_check_shmdt_t (struct ucred *cred, struct shmid_kernel *shmsegptr, struct label *shmseglabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_sysvshm_check_shmget_t (struct ucred *cred, struct shmid_kernel *shmsegptr, struct label *shmseglabel, int shmflg) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}


/* thread */

/* vnode */
static int
casper_mpo_vnode_check_access_t (struct ucred *cred, struct vnode *vp, struct label *vplabel, accmode_t accmode) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns")) {
        return EACCES;
    }
    return 0;
}
static int
casper_mpo_vnode_check_chdir_t (struct ucred *cred, struct vnode *dvp, struct label *dvplabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_chroot_t (struct ucred *cred, struct vnode *dvp, struct label *dvplabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_create_t (struct ucred *cred, struct vnode *dvp, struct label *dvplabel, struct componentname *cnp, struct vattr *vap) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_deleteacl_t (struct ucred *cred, struct vnode *vp, struct label *vplabel, acl_type_t type) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_deleteextattr_t (struct ucred *cred, struct vnode *vp, struct label *vplabel, int attrnamespace, const char *name) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_exec_t (struct ucred *cred, struct vnode *vp, struct label *vplabel, struct image_params *imgp, struct label *execlabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_getacl_t (struct ucred *cred, struct vnode *vp, struct label *vplabel, acl_type_t type) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_getextattr_t (struct ucred *cred, struct vnode *vp, struct label *vplabel, int attrnamespace, const char *name) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_link_t (struct ucred *cred, struct vnode *dvp, struct label *dvplabel, struct vnode *vp, struct label *vplabel, struct componentname *cnp) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_listextattr_t (struct ucred *cred, struct vnode *vp, struct label *vplabel, int attrnamespace) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_lookup_t (struct ucred *cred, struct vnode *dvp, struct label *dvplabel, struct componentname *cnp) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns")) {
        return EACCES;
    }
    return 0;
}
static int
casper_mpo_vnode_check_mmap_t (struct ucred *cred, struct vnode *vp, struct label *label, int prot, int flags) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_mprotect_t(struct ucred *cred, struct vnode *vp, struct label *vplabel, int prot) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
// static int
// casper_mpo_vnode_check_open(struct ucred *cred, struct vnode *vp, struct label *label, int acc_mode)
// {
//     char *filename = NULL, *freebuf = NULL;
//     int error;
//
//     // Check if the credentials are valid
//     if (cred == NULL) {
//         return 0;
//     }
//
//     // Restrict access for CASPER_DNS_UID
//     if (cred->cr_ruid == CASPER_DNS_UID) {
//         error = vn_fullpath(vp, &filename, &freebuf);
//
//         // If we can't determine the path, allow access (fail-safe)
//         if (error != 0 || filename == NULL) {
//             return 0;
//         }
//
//         // Allow access to /etc/hosts, /lib/, and /usr/lib/
//         if (
//             strcmp(filename, "/etc/nsswitch.conf") != 0 &&
//             strcmp(filename, "/etc/hosts") != 0 &&
//             strcmp(filename, "/etc/resolv.conf") != 0 &&
//             strcmp(filename, "/etc/services") != 0
//             // && strncmp(filename, "/lib/", 5) != 0 &&
//             // strncmp(filename, "/usr/lib/", 9) != 0
//             )
//         {
//             free(freebuf, M_TEMP);
//             return (EACCES); // Deny access
//         }
//
//         // Free the buffer if allocated
//         free(freebuf, M_TEMP);
//     }
//
//     return 0; // Allow other access
// }
static int
casper_mpo_vnode_check_open(struct ucred *cred, struct vnode *vp, struct label *label, int acc_mode)
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
        if (!strcmp(obj->original_filename, "/etc/nsswitch.conf") ||
            !strcmp(obj->original_filename, "/etc/hosts") ||
            !strcmp(obj->original_filename, "/etc/resolv.conf") ||
            !strcmp(obj->original_filename, "/etc/services"))
        {
            obj->original_filename[0] = '\0';
            return 0;
        }

        // Get the full path of the vnode
        error = vn_fullpath(vp, &filename, &freebuf);

        // If full path retrieval fails, allow access (fail-safe policy)
        if (error != 0 || filename == NULL) {
            return 0;
        }

        // Restrict access to specific paths
        if (strcmp(filename, "/etc/nsswitch.conf") != 0 &&
            strcmp(filename, "/etc/hosts") != 0 &&
            strcmp(filename, "/etc/resolv.conf") != 0 &&
            strcmp(filename, "/etc/services") != 0)
        {
            free(freebuf, M_TEMP); // Free allocated buffer
            return (EACCES);      // Deny access
        }

        // Free allocated buffer after successful checks
        free(freebuf, M_TEMP);
    }

    return 0; // Allow access for other labels or conditions
}
static int
casper_mpo_vnode_check_poll_t (struct ucred *active_cred, struct ucred *file_cred, struct vnode *vp, struct label *vplabel) {
    if (active_cred == NULL || active_cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(active_cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_read_t (struct ucred *active_cred, struct ucred *file_cred, struct vnode *vp, struct label *vplabel) {
    return 0; // Allow other access
}
static int
casper_mpo_vnode_check_readdir_t (struct ucred *cred, struct vnode *dvp, struct label *dvplabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_readlink_t (struct ucred *cred, struct vnode *vp, struct label *vplabel) {
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
        if (!strcmp(obj->original_filename, "/etc/nsswitch.conf") ||
            !strcmp(obj->original_filename, "/etc/hosts") ||
            !strcmp(obj->original_filename, "/etc/resolv.conf") ||
            !strcmp(obj->original_filename, "/etc/services"))
        {
            return 0;
        }


        // Get the full path of the vnode
        error = vn_fullpath(vp, &filename, &freebuf);

        // If full path retrieval fails, allow access (fail-safe policy)
        if (error != 0 || filename == NULL) {
            return 0;
        }

        // Restrict access to specific paths
        if (strcmp(filename, "/etc/nsswitch.conf") != 0 &&
            strcmp(filename, "/etc/hosts") != 0 &&
            strcmp(filename, "/etc/resolv.conf") != 0 &&
            strcmp(filename, "/etc/services") != 0)
        {
            free(freebuf, M_TEMP); // Free allocated buffer
            return (EACCES);      // Deny access
        }

        strlcpy(obj->original_filename, filename, sizeof(obj->original_filename));

        // Free allocated buffer after successful checks
        free(freebuf, M_TEMP);
    }

    return 0; // Allow access for other labels or conditions
}
static int
casper_mpo_vnode_check_relabel_t (struct ucred *cred, struct vnode *vp, struct label *vplabel, struct label *newlabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_rename_from_t (struct ucred *cred, struct vnode *dvp, struct label *dvplabel, struct vnode *vp, struct label *vplabel, struct componentname *cnp) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_rename_to_t (struct ucred *cred, struct vnode *dvp, struct label *dvplabel, struct vnode *vp, struct label *vplabel, int samedir, struct componentname *cnp) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_revoke_t (struct ucred *cred, struct vnode *vp, struct label *vplabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_setacl_t (struct ucred *cred, struct vnode *vp, struct label *vplabel, acl_type_t type, struct acl *acl) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_setextattr_t (struct ucred *cred, struct vnode *vp, struct label *vplabel, int attrnamespace, const char *name) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_setflags_t (struct ucred *cred, struct vnode *vp, struct label *vplabel, u_long flags) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_setmode_t (struct ucred *cred, struct vnode *vp, struct label *vplabel, mode_t mode) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_setowner_t (struct ucred *cred, struct vnode *vp, struct label *vplabel, uid_t uid, gid_t gid) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_setutimes_t (struct ucred *cred, struct vnode *vp, struct label *vplabel, struct timespec atime, struct timespec mtime) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_stat_t (struct ucred *active_cred, struct ucred *file_cred, struct vnode *vp, struct label *vplabel) {
    if (active_cred == NULL || active_cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(active_cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_unlink_t (struct ucred *cred, struct vnode *dvp, struct label *dvplabel, struct vnode *vp, struct label *vplabel, struct componentname *cnp) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_check_write_t (struct ucred *active_cred, struct ucred *file_cred, struct vnode *vp, struct label *vplabel) {
    if (active_cred == NULL || active_cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(active_cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;;
}
static int
casper_mpo_vnode_create_extattr_t (struct ucred *cred, struct mount *mp, struct label *mplabel, struct vnode *dvp, struct label *dvplabel, struct vnode *vp, struct label *vplabel, struct componentname *cnp) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_execve_will_transition_t (struct ucred *old, struct vnode *vp, struct label *vplabel, struct label *interpvplabel, struct image_params *imgp, struct label *execlabel) {
    if (old == NULL || old->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(old->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}
static int
casper_mpo_vnode_setlabel_extattr_t (struct ucred *cred, struct vnode *vp, struct label *vplabel, struct label *intlabel) {
    if (cred == NULL || cred->cr_label == NULL)
        return 0;
    struct mac_casper *obj = SLOT(cred->cr_label);
    if (obj == NULL)
        return 0;
    if (!strcmp(obj->label, "dns"))
        return EACCES;
    return 0;
}

/* init */
static void
casper_init(struct mac_policy_conf *conf)
{
    printf("\ncasper_init start\n");
    /* Check if zone_casper is already created */
    zone_casper = uma_zcreate("mac_casper", sizeof(struct mac_casper), NULL,
            NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
    if (zone_casper == NULL) {
        /* Handle memory allocation failure */
        printf("Failed to create uma zone for casper\n");
        return;
    }
    printf("\ncasper_init end\n");
}
static void
casper_destroy(struct mac_policy_conf *mpc)
{
    if (zone_casper != NULL) {
        uma_zdestroy(zone_casper);
        zone_casper = NULL;
    }
}

/* Base structure */
static struct mac_policy_ops caspe_mac_policy_ops = {
    /* init */
    .mpo_init = casper_init,
    .mpo_destroy = casper_destroy,
    /* bpfdsec */
    /* cred */
    // .mpo_cred_check_relabel = ... // Allow relabel
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
    .mpo_cred_destroy_label = casper_cred_destroy_label, // Free the tag memory
    .mpo_cred_internalize_label = casper_mpo_cred_internalize_label_t, // Give tag name
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
    .mpo_socket_check_connect = casper_mpo_socket_check_connect_t, // TODO
    // .mpo_socket_check_create = casper_mpo_socket_check_create_t, // Enable
    .mpo_socket_check_listen = casper_mpo_socket_check_listen_t,
    // .mpo_socket_check_poll = casper_mpo_socket_check_poll_t, // Enable for IPC
    // .mpo_socket_check_receive = casper_mpo_socket_check_receive_t, // Enable
    .mpo_socket_check_relabel = casper_mpo_socket_check_relabel_t,
    .mpo_socket_check_send = casper_mpo_socket_check_send_t, // TODO
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
    .mpo_vnode_check_open = casper_mpo_vnode_check_open,
    .mpo_vnode_check_poll = casper_mpo_vnode_check_poll_t,
    // .mpo_vnode_check_read = casper_mpo_vnode_check_read_t, // Enable
    .mpo_vnode_check_readdir = casper_mpo_vnode_check_readdir_t,
    .mpo_vnode_check_readlink = casper_mpo_vnode_check_readlink_t,
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
    .mpo_vnode_execve_will_transition = casper_mpo_vnode_execve_will_transition_t,
    .mpo_vnode_setlabel_extattr = casper_mpo_vnode_setlabel_extattr_t,
};

/* Register */
MAC_POLICY_SET(&caspe_mac_policy_ops, CaspeMAC, "Caspe MAC policy", MPC_LOADTIME_FLAG_UNLOADOK, &casper_slot);
