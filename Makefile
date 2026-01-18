.include <bsd.own.mk>

KMOD=   mac_policy_ops
SRCS=   mac_policy_ops.c
SRCS+=	checker/checker.c
SRCS+=	vnode_if.h
SRCS+=  label.h

.include <bsd.kmod.mk>
