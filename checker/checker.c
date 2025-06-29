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
casper_check_dst_ip(const char *label, struct sockaddr *sa)
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

	if (!label || !sa)
		return (EINVAL);

	// Assign check file
	if (strcmp(label, "dns") == 0)
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
