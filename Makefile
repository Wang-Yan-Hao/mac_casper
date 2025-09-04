.include <bsd.own.mk>

KMOD=   mac_casper
SRCS=   mac_casper.c
SRCS+=	checker/checker.c
SRCS+=	vnode_if.h
SRCS+=  label.h

.include <bsd.kmod.mk>
