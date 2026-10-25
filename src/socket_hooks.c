#include "internal.h"

/* socket */
int
casper_mpo_socket_check_accept_t(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_socket_check_bind_t(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa)
{
	struct mac_casper *obj = casper_get_label(cred);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_DNS || obj->type == SUB_FILEARGS ||
	    obj->type == SUB_GRP || obj->type == SUB_NETDB ||
	    obj->type == SUB_PWD || obj->type == SUB_SYSCTL ||
	    obj->type == SUB_SYSLOG)
		return (EACCES);

	return (0);
}
int
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
int
casper_mpo_socket_check_create_t(struct ucred *cred, int domain, int type,
    int protocol)
{
	struct mac_casper *obj = casper_get_label(cred);
	if (obj == NULL)
		return (0);

	if (obj->type == SUB_DNS || obj->type == SUB_NET)
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
int
casper_mpo_socket_check_listen_t(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	return casper_deny_default(cred);
}
int
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
int
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
int
casper_mpo_socket_check_relabel_t(struct ucred *cred, struct socket *so,
    struct label *solabel, struct label *newlabel)
{
	return casper_deny_default(cred);
}
int
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
int
casper_mpo_socket_check_stat_t(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	return casper_deny_default(cred);
}
int
casper_mpo_socket_check_visible_t(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	return casper_deny_default(cred);
}
/* socketpeer */
/* syncache */
