CC=		cc
ITERATIONS?=	100000
CFLAGS=		-O0 -DITERATIONS=${ITERATIONS}

PROGS=	perf_baseline \
		perf_dns \
		perf_fileargs \
		perf_grp \
		perf_netdb \
		perf_pwd \
		perf_sysctl \
		perf_syslog

all: ${PROGS}

${PROGS}: perf_multi.c
	@case $@ in \
		perf_baseline) ${CC} ${CFLAGS} -o $@ perf_multi.c ;; \
		perf_dns)      ${CC} ${CFLAGS} -DMAC_DNS -o $@ perf_multi.c ;; \
		perf_fileargs) ${CC} ${CFLAGS} -DMAC_FILEARGS -o $@ perf_multi.c ;; \
		perf_grp)      ${CC} ${CFLAGS} -DMAC_GRP -o $@ perf_multi.c ;; \
		perf_netdb)    ${CC} ${CFLAGS} -DMAC_NETDB -o $@ perf_multi.c ;; \
		perf_pwd)      ${CC} ${CFLAGS} -DMAC_PWD -o $@ perf_multi.c ;; \
		perf_sysctl)   ${CC} ${CFLAGS} -DMAC_SYSCTL -o $@ perf_multi.c ;; \
		perf_syslog)   ${CC} ${CFLAGS} -DMAC_SYSLOG -o $@ perf_multi.c ;; \
	esac

clean:
	rm -f ${PROGS}
