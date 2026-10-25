#include "src/internal.h"

int casper_slot;

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
	.mpo_cred_check_visible = casper_mpo_cred_check_visible_t, // Check
	/* ddb */
	/* devfs */
	/* ifnet */
	.mpo_ifnet_check_relabel = casper_mpo_ifnet_check_relabel_t,
	/* inpcb */
	.mpo_inpcb_check_visible = casper_mpo_inpcb_check_visible_t, // Check
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
	// If you want debug which file it open, uncomment below
	//.mpo_vnode_check_lookup = casper_mpo_vnode_check_lookup, // Allow
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
