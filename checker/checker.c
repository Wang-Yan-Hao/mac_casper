#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/domain.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/vnode.h>

#include "../label.h"
#include "../mac_casper.h"
#include "checker.h"

/* Check open files in white list */
int
casper_check_allowed_open(struct mac_casper *subj, struct mac_casper *obj)
{
	const struct cas_access_rule *rule;
	const enum cas_obj_label *ptr;
	enum cas_sub_label subj_type;
	enum cas_obj_label obj_type;

	if (subj == NULL || obj == NULL)
		return (0);

	subj_type = (enum cas_sub_label)subj->type;
	obj_type = (enum cas_obj_label)obj->type;

	if (subj_type <= SUB_NONE || subj_type >= SUB_LABEL_LEN ||
	    subj_type == SUB_FILEARGS)
		return (0);

	printf("casper_check_allowed_open(): subj_type %d, obj_type %d\n",
	    subj_type, obj_type);

	for (rule = casper_open_map; rule->subj != SUB_NONE; rule++) {
		if (rule->subj == subj_type) {
			for (ptr = rule->allowed_list; *ptr != OBJ_NONE;
			    ptr++) {
				if (*ptr == obj_type) {
					printf(
					    "casper_check_allowed_open() return 0\n");
					return (0);
				}
			}

			printf("casper_check_allowed_open() return EACCESS\n");
			return (EACCES);
		}
	}

	printf("casper_check_allowed_open() return EACCESS\n");
	return (EACCES);
}
