# Effectiveness Evaluation

This directory contains the effectiveness evaluation framework for the `mac_casper` project. The goal of this evaluation is to verify whether the MAC policy correctly intercepts and blocks unauthorized or malicious system calls executed inside a Casper sandboxed service.

To perform the evaluation, we inject simulated attack payloads (Attack Harnesses) directly into the `system.grp` service and trigger them from a client application. The MAC framework should prevent these malicious operations if the policy is correctly enforced.

## Directory Structure

```sh
.
├── casper_src/
│   └── cap_grp.c        # Patched Casper GRP service with ATTACK_* commands
├── main.c               # Client program that triggers attack commands
└── Makefile             # Build script for the client program
```
* `casper_src/cap_grp.`c
    Modified version of the Casper system.grp service that includes several ATTACK_* commands used to simulate malicious behaviors (e.g., executing binaries, reading sensitive files, network access).
* `main.c`
    Client application that sends attack commands to the patched system.grp service via IPC (`cap_xfer_nvlist`).
* Makefile
    Used to build the client program.

## Evaluation Setup

Before running the evaluation, the system's original `cap_grp.c` must be replaced with our patched version containing the simulated attacks.

## Replace the Original Casper Source

Locate the original `cap_grp.c` in the FreeBSD source tree. Backup the original file and replace it with the patched version:

```bash
# Backup original source
sudo cp /usr/src/lib/libcasper/services/cap_grp/cap_grp.c /usr/src/lib/libcasper/services/cap_grp/cap_grp.c.bak

# Patch casper service
sudo install -m 644 casper_src/cap_grp.c /usr/src/lib/libcasper/services/cap_grp/cap_grp.c
```

## Rebuild and Install the Casper Service

Recompile and reinstall the modified service:

```bash
cd /usr/src/lib/libcasper/

sudo make all install
```

This step installs the patched `system.grp` service containing the attack harness.

---

## Build and Run

Return to this evaluation directory and compile, running the client:

```bash
make
./main <ATTACK_TYPE>
```

The program sends `ATTACK_*` commands to the patched `system.grp` service.

## Expected Results

The evaluation is designed to bypass standard Discretionary Access Control (DAC) limitations. The test cases utilize operations that a normal unprivileged user is legally allowed to perform under standard DAC (e.g., reading `/etc/passwd` or writing to `/tmp`), ensuring that any interception is strictly the result of the CasperMAC policy.

The detailed expected outcomes for each attack vector are as follows:

| Attack Command | Target Operation | Expected Result (MAC Enabled) | Reason / Explanation |
| :--- | :--- | :--- | :--- |
| `ATTACK_EXEC` | `fork` + `execve("/bin/sleep")` | **Blocked** (`errno = 10: ECHILD`) | The MAC policy prevents the sandboxed process from executing new binaries. The child process is killed/reaped immediately, so the parent cannot `wait` for it and receives `errno = 10`. |
| `ATTACK_FILE_READ` | `open("/etc/passwd", O_RDONLY)` | **Blocked** (`errno = 13: EACCES`) | Reading global system files is prohibited. The target is world-readable, proving MAC intervention rather than standard DAC limits. |
| `ATTACK_FILE_WRITE`| `open("/tmp/mac_casper_write_test", ...)` | **Blocked** (`errno = 13: EACCES`) | Writing to the filesystem, even to world-writable directories like `/tmp`, is denied by the sandbox policy. |
| `ATTACK_CRED` | `setuid(getuid())` | **Blocked** (`errno = 13: EACCES`) | The MAC policy explicitly restricts credential manipulation, even for the user's own UID. |
| `ATTACK_NET` | `socket()` & `connect()` to Loopback | **Blocked** (`errno = 13: EACCES`) | The `system.grp` service does not require network access; MAC successfully blocks socket creation and connection operations. |
| `ATTACK_IPC` | `shm_open("/mac_casper_test", ...)` | **Blocked** (`errno = 13: EACCES`) | POSIX shared memory and other Inter-Process Communication (IPC) mechanisms are restricted to maintain strict isolation. |
| `ATTACK_KLD` | `kldfind("kernel")` | **Blocked** (`errno = 13: EACCES`) | Probing for loaded kernel modules is blocked to prevent information leaks regarding the kernel environment. |
| `ATTACK_SYSCTL` | `sysctlbyname("kern.ostype", ...)` | **Blocked** (`errno = 13: EACCES`) | Reading global system state variables via `sysctl` is denied by the sandbox policy. |

