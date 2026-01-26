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

#include <netinet/in.h>
#include <netinet/ip6.h>

#include "../label.h"
#include "../mac_policy_ops.h"
#include "checker.h"

struct casper_dns_cache dns_cache;

/* DNS Checker */

void
casper_dns_init(void)
{
	rm_init(&dns_cache.lock, "casper_dns_lock");
	dns_cache.count = 0;
}

void
casper_dns_destroy(void)
{
	rm_destroy(&dns_cache.lock);
}

int
casper_check_dst_ip(const int type, struct sockaddr *sa)
{
	printf("casper_check_dst_ip() start\n");
	struct rm_priotracker tracker;
	struct sockaddr *cached_sa;
	struct sockaddr_in *dst_in, *cached_in;
	struct sockaddr_in6 *dst_in6, *cached_in6;
	int i, error = EACCES;

	if (sa == NULL)
		return (EINVAL);

	if (type != SUB_DNS)
		return (0);

	rm_rlock(&dns_cache.lock, &tracker);

	if (dns_cache.count == 0) {
		rm_runlock(&dns_cache.lock, &tracker);
		return (EACCES);
	}

	/* 3. 印出當前正在連線的 IP (Incoming) */
	if (sa->sa_family == AF_INET) {
		dst_in = (struct sockaddr_in *)sa;
		printf("Casper Check: Incoming IPv4 (Raw Hex): 0x%08x\n",
			   ntohl(dst_in->sin_addr.s_addr));
	} else if (sa->sa_family == AF_INET6) {
		printf("Casper Check: Incoming is IPv6\n");
	} else {
		printf("Casper Check: Incoming Unknown Family: %d\n", sa->sa_family);
	}

	for (i = 0; i < dns_cache.count; i++) {
		cached_sa = (struct sockaddr *)&dns_cache.ns[i];

		if (sa->sa_family != cached_sa->sa_family)
			continue;

		if (sa->sa_family == AF_INET) {
			dst_in = (struct sockaddr_in *)sa;
			cached_in = (struct sockaddr_in *)cached_sa;

			/* 把兩個數值都印出來，一看就知道為什麼不相等 */
			printf("  [%d] Compare: 0x%08x (Dest) vs 0x%08x (Cache)\n",
				   i, ntohl(dst_in->sin_addr.s_addr), ntohl(cached_in->sin_addr.s_addr));

			if (dst_in->sin_addr.s_addr == cached_in->sin_addr.s_addr) {
				error = 0; /* Match! */
				break;
			}
		}
		else if (sa->sa_family == AF_INET6) {
			dst_in6 = (struct sockaddr_in6 *)sa;
			cached_in6 = (struct sockaddr_in6 *)cached_sa;

			if (IN6_ARE_ADDR_EQUAL(&dst_in6->sin6_addr,
				&cached_in6->sin6_addr)) {
				error = 0; /* Match! */
				break;
			}
			printf("  [%d] IPv6 mismatch\n", i);
		}
	}

	printf("casper_check_dst_ip() done, error is %d\n", error);

	rm_runlock(&dns_cache.lock, &tracker);

	return (error);
}

/* Open Checker */

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
