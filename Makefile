.include <bsd.own.mk>

KMOD=   mac_policy_ops
SRCS=   mac_policy_ops.c
SRCS+=	vnode_if.h

.include <bsd.kmod.mk>
