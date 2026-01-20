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

/*
 * "/etc/resolv.conf" parser is implement in userspace
 * library res_init() function. We implment a kernel
 * version parser like how res_init() parse.
 */
static char *
casper_get_nameserver(char *line)
{
	if (strncmp(line, "nameserver", 10) == 0) {
		char *line_start;

		line_start = line + sizeof("nameserver") - 1;
		while (*line_start == ' ' || *line_start == '\t')
			line_start++;

		line_start[strcspn(line_start, ";# \t\n")] = '\0';
		if ((*line_start != '\0') && (*line_start != '\n'))
			return line_start;
	}

	return NULL;
}

static bool
nameserver_match(char *line, struct sockaddr *sa, bool *pass, int *nserv)
{
	char *ip = casper_get_nameserver(line);
	if (!ip || *nserv >= MAXNS)
		return false;

	// TODO add cache for three nameserver
	// May use time to check wheather the file
	// change
	if (sa->sa_family == AF_INET) { // AF_INET
		struct in_addr found_ip4,
		    ipv4_exp_addr = ((struct sockaddr_in *)sa)->sin_addr;

		if (inet_pton(AF_INET, ip, &found_ip4) == 1 &&
		    found_ip4.s_addr == ipv4_exp_addr.s_addr)
			*pass = true;

	} else { // AF_INET6
		struct in6_addr found_ip6,
		    ipv6_exp_addr = ((struct sockaddr_in6 *)sa)->sin6_addr;

		if (inet_pton(AF_INET6, ip, &found_ip6) == 1 &&
		    memcmp(&found_ip6, &ipv6_exp_addr,
			sizeof(struct in6_addr)) == 0)
			*pass = true;
	}

	(*nserv)++;
	return false;
}

/* DNS checker */
int
casper_check_dst_ip(const int type, struct sockaddr *sa)
{
	char *check_filepath, *buf, *line_start, *newline;
	int error = 0, nserv = 0, read_once = 0;
	bool pass = false;
	struct nameidata nd;
	struct vnode *vp;
	struct uio auio;
	struct iovec aiov;
	off_t offset = 0;
	size_t bytes_read = 0;

	if (!(type > 0 && type < SUB_LABEL_LEN) || sa == NULL)
		return (EINVAL);

	// Assign check file
	if (type == SUB_DNS)
		check_filepath = "/etc/resolv.conf";
	else
		return (ENOTSUP);

	// Get connect dst ip
	if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)
		return (EAFNOSUPPORT);

	// Get vnode of the check file path
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE, check_filepath);

	error = namei(&nd);
	if (error)
		return error;
	vp = nd.ni_vp;

	if (vp->v_type != VREG) {
		vput(vp);
		NDFREE_PNBUF(&nd);
		return (EINVAL);
	}

	buf = (char *)malloc(BUF_SIZE, M_TEMP, M_WAITOK | M_ZERO);
	if (!buf)
		return (ENOMEM);

	/*
	 * Userspace "/etc/resolv.conf" parser use fgets to
	 * parse. Here we implement a kernel version fgets.
	 */
	read_once = BUF_SIZE - 1; // leave space for \0
	while (1) {
		aiov.iov_base = buf;
		aiov.iov_len = read_once;

		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = offset;
		auio.uio_resid = read_once;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_rw = UIO_READ;
		auio.uio_td = curthread;

		// Clean buffer
		memset(buf, 0, BUF_SIZE);

		// Non-blocking
		error = VOP_READ(vp, &auio, IO_NODELOCKED | IO_UNIT,
		    curthread->td_ucred);
		if (error) {
			vput(vp);
			NDFREE_PNBUF(&nd);
			free(buf, M_TEMP);
			return error;
		}

		if (auio.uio_resid == read_once) // EOF
			break;

		bytes_read = read_once - auio.uio_resid;
		offset += bytes_read;
		buf[bytes_read] = '\0'; // Append '\0'

		line_start = buf;
		while (
		    (newline = memchr(line_start, '\n', bytes_read)) != NULL) {
			*newline = '\0';
			if (nameserver_match(line_start, sa, &pass, &nserv))
				goto done;
			line_start = newline + 1;
		}

		if (line_start == buf) {
			if (nameserver_match(line_start, sa, &pass, &nserv))
				goto done;
		} else
			offset -= (bytes_read - (line_start - buf));
	}
done:
	vput(vp);
	NDFREE_PNBUF(&nd);
	free(buf, M_TEMP);
	return (pass ? 0 : EACCES);
}

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

/*
static int
casper_check_allowed_file(char *original_filename, struct vnode *vp,
    const char *const *allowed_paths)
{
	if (vp == NULL)
		return (0);

	char *filename = NULL, *freebuf = NULL;
	int error;

	// Check soft link (original filename)
	for (int i = 0; allowed_paths[i] != NULL; i++) {
		if (strcmp(original_filename, allowed_paths[i]) == 0) {
			((char *)original_filename)[0] = '\0';
			return (0);
		}
	}

	// Resolve full path of vnode
	error = vn_fullpath(vp, &filename, &freebuf);
	if (error != 0 || filename == NULL)
		return (0); // fail-safe allow

	// Compare full path with whitelist
	for (int i = 0; allowed_paths[i] != NULL; i++) {
		if (strcmp(filename, allowed_paths[i]) == 0) {
			free(freebuf, M_TEMP);
			return (0);
		}
	}

	free(freebuf, M_TEMP);
	return (EACCES);
}
static int
casper_check_allowed_file_on_readlink(char *original_filename, struct vnode *vp,
    const char *const *allowed_paths, struct mac_casper *obj)
{
	if (vp == NULL)
		return (0);

	char *filename = NULL, *freebuf = NULL;
	int error;

	// Check soft link (original filename)
	for (int i = 0; allowed_paths[i] != NULL; i++) {
		if (strcmp(original_filename, allowed_paths[i]) == 0)
			return (0);
	}

	error = vn_fullpath(vp, &filename, &freebuf);
	if (error != 0 || filename == NULL)
		return (0);

	int allowed = 0;
	for (int i = 0; allowed_paths[i] != NULL; i++) {
		if (strcmp(filename, allowed_paths[i]) == 0) {
			allowed = 1;
			break;
		}
	}

	free(freebuf, M_TEMP);

	if (!allowed)
		return (EACCES);
	else {
		strlcpy(obj->original_filename, filename,
		    sizeof(obj->original_filename));
		return (0);
	}
}
*/
