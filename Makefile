.include <bsd.own.mk>

KMOD=   mac_casper
SRCS=   mac_casper.c
SRCS+=	src/default_hooks.c
SRCS+=	src/cred_hooks.c
SRCS+=	src/inpcb_hooks.c
SRCS+=	src/system_hooks.c
SRCS+=	src/socket_hooks.c
SRCS+=	src/vnode_hooks.c
SRCS+=	src/label_hooks.c
SRCS+=	mac_casper.h
SRCS+=	src/internal.h
SRCS+=	checker.c
SRCS+=	checker.h
SRCS+=  label.h
SRCS+=	vnode_if.h

.include <bsd.kmod.mk>
