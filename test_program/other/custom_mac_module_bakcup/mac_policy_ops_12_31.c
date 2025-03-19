
#include <sys/param.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/module.h>
#include <security/mac/mac_policy.h>

static int caspe_mac_check_vnode_open(struct ucred *cred, struct vnode *vp, struct label *label, int acc_mode);
// static void caspe_mac_init(struct mac_policy_ops *mpo);
// static void caspe_mac_destroy(struct mac_policy_ops *mpo);

static struct mac_policy_ops caspe_mac_policy_ops = {
    .mpo_vnode_check_open = caspe_mac_check_vnode_open,
    // .mpo_init = caspe_mac_init,
    // .mpo_destroy = caspe_mac_destroy,
};

// static struct mac_policy_conf caspe_mac_policy_conf = {
//     .mpc_name = "CaspeMAC",
//     .mpc_ops = &caspe_mac_policy_ops,
//     .mpc_loadtime_flags = MPC_LOADTIME_FLAG_UNLOADOK,
//     .mpc_field_off = 0,  // No private data
// };

static int
caspe_mac_check_vnode_open(struct ucred *cred, struct vnode *vp, struct label *label, int acc_mode)
{
    char *filename = NULL;
    char *freebuf = NULL;
    int error;

    /* Ensure cred is not NULL and fetch the file path (filename) */
    if (cred == NULL) {
        return (0);  /* If no credentials, allow the access */
    }


    /* Restrict 'caspe' user to only access '/etc/hosts' */
    if (cred->cr_ruid == 1002) {  /* 'caspe' user has UID 1002 */
    error = vn_fullpath(vp, &filename, &freebuf);
    if (error != 0 || filename == NULL) {
        return (0);  /* If path can't be determined, allow the access */
    }
        if (strcmp(filename, "/etc/hosts") != 0) {
            free(freebuf, M_TEMP);  /* Free the buffer after use */
            return (EACCES);  /* Deny access to any file other than /etc/hosts */
        }
    free(freebuf, M_TEMP);  /* Free the buffer after use */
	}

    return (0);  /* Allow access otherwise */
}

// static void
// caspe_mac_init(struct mac_policy_ops *mpo)
// {
//     /* Initialize the policy (if needed, allocate resources) */
// }
//
// static void
// caspe_mac_destroy(struct mac_policy_ops *mpo)
// {
//     /* Clean up resources when the module is unloaded */
// }

MAC_POLICY_SET(&caspe_mac_policy_ops, CaspeMAC, "Caspe MAC policy", MPC_LOADTIME_FLAG_UNLOADOK, 0);
