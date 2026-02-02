.include <bsd.own.mk>

KMOD=   mac_casper
SRCS=   mac_casper.c
SRCS+=	mac_casper.h
SRCS+=	checker.c
SRCS+=	checker.h
SRCS+=  label.h
SRCS+=	vnode_if.h

.include <bsd.kmod.mk>
