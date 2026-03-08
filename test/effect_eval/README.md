# Effectiveness Evaluation

This directory contains the effectiveness evaluation framework for the **`mac_casper`** project. The goal of this evaluation is to verify whether the MAC policy correctly **intercepts and blocks unauthorized or malicious system calls** executed inside a Casper sandboxed service.

To perform the evaluation, we inject **simulated attack payloads (Attack Harnesses)** directly into the `system.dns` service and trigger them from a client application. The MAC framework should prevent these malicious operations if the policy is correctly enforced.

## Directory Structure

```sh
.
├── casper_src/
│   └── cap_dns.c        # Patched Casper DNS service with ATTACK_* commands
├── main.c               # Client program that triggers attack commands
└── Makefile             # Build script for the client program
```

* `casper_src/cap_dns.c`
  Modified version of the Casper `system.dns` service that includes several `ATTACK_*` commands used to simulate malicious behaviors.
* `main.c`
  Client application that sends attack commands to the patched `system.dns` service.
* `Makefile`
  Used to build the client program.

## Evaluation Setup

Before running the evaluation, the system's original `cap_dns.c` must be replaced with our patched version containing the simulated attacks.

## Replace the Original Casper Source

Locate the original `cap_dns.c` in the FreeBSD source tree. Backup the original file and replace it with the patched version:

```bash
cd /usr/src/lib/libcasper/services/cap_dns/

# Backup original source
sudo cp cap_dns.c cap_dns.c.bak

# Replace with patched version
sudo cp ~/git_projects/mac_casper/test/effect_eval/casper_src/cap_dns.c .
```

## Rebuild and Install the Casper DNS Service

Recompile and reinstall the modified service:

```bash
cd /usr/src/lib/libcasper/services/cap_dns/

sudo make clean
sudo make
sudo make install
```

This step installs the patched `system.dns` service containing the attack harness.

---

## Build the Client Program

Return to this evaluation directory and compile the client:

```bash
make
```

This will build the executable `main`.

## 4. Run the Evaluation

Execute the client program to trigger the simulated attacks:

```bash
./main
```

The program sends `ATTACK_*` commands to the patched `system.dns` service.
If the MAC policy is correctly implemented, the malicious system calls should be **intercepted and blocked**.

## Expected Results

* Without the MAC policy:
  The injected attack payloads may successfully execute restricted system calls.

* With the MAC policy enabled:
  The policy should intercept and block these calls, preventing the attack from succeeding.

The output logs can be used to verify whether the MAC enforcement behaves as expected.
