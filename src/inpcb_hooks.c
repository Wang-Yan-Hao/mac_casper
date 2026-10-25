#include "internal.h"

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
