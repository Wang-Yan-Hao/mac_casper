# MAC policy sources

The kernel module's policy ops table and `MAC_POLICY_SET` registration are in
[`../mac_casper.c`](../mac_casper.c). Hook functions are grouped by callback
category:

- `default_hooks.c`: hooks that use the default deny decision.
- `cred_hooks.c`: credential checks, including visibility checks.
- `inpcb_hooks.c`: inpcb visibility checks.
- `socket_hooks.c`: socket checks.
- `system_hooks.c`: system checks, including the service-specific sysctl rule.
- `vnode_hooks.c`: vnode permission checks.
- `label_hooks.c`: policy initialization and credential/vnode label callbacks.
- `internal.h`: declarations shared by the hook files and policy ops table.

Every source file is listed in the root `Makefile`. Keep the callback
definitions, declarations, and designated initializers in the ops table in
sync when adding or moving hooks. Changes to hook behavior should be reviewed
separately from file-only refactors.

Build this module on a compatible FreeBSD system; the source depends on
FreeBSD kernel and MAC framework headers.
