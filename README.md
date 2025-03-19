# mac_casper

## Introduction

The `casper` framework in FreeBSD is designed to help applications minimize their access to system resources by using capabilities. When an application interacts with a `casper` service, it does so with limited permissions, relying on `casper` to perform specific privileged operations on its behalf. This design allows applications to avoid needing full system access while still performing necessary tasks securely.

To fulfill its role, `casper` typically requires broad access to system resources. For example:

- A `casper` service handling DNS resolution may need access to network interfaces.
- A service managing user credentials may require access to sensitive system files.

As a result, `casper` services often have more extensive access rights than the applications they support. However, if a `casper` service is compromised, it could allow an attacker to exploit this broad access, undermining the security benefits provided by the capability-based restrictions on the application itself.

This project implements a MAC (Mandatory Access Control) module to sandbox the `casper` service, enhancing its security and reducing the impact of potential vulnerabilities.

---

## Build and Run

To build and install the project, run:

```sh
make all
make install

# Alternatively, with root privileges:
sudo make all install
```

Use below to load kernel module
```sh
sh script/unload_load.sh
```

Below show how to test
```sh
cd test_program
make
./getaddr
```

## Limit privileged

![image](https://github.com/user-attachments/assets/16e1e28b-5505-4208-ab16-e1e2e37fc3bd)

In Casper ([libcasper(3)](https://man.freebsd.org/cgi/man.cgi?query=libcasper&apropos=0&sektion=3&manpath=FreeBSD+15.0-CURRENT&arch=default&format=html)), multiple services run independently, and each should have its own namespace. Below is an overview of the required permissions for each service:  

### DNS  
The DNS service should be able to open, read, and perform lookups on the following files:  
1. `/etc/services`  
2. `/etc/nsswitch.conf`  
3. `/etc/resolv.conf`  
4. `/etc/hosts`  

Additionally, it should only be allowed to connect and send requests to the servers listed in `/etc/resolv.conf`. It may also perform receive system calls.  
All other system calls should be restricted.  

### Net  
Similar to the DNS service, the Net service has network-related permissions but is more general. It is allowed to connect and bind to user-defined IP lists.  
All other system calls should be restricted.  

### FileArgs  
This service is responsible for opening user-defined files.  
All other system calls should be restricted.  

### Group (Grp)  
This service should only be allowed to open the following files:  
1. `/etc/group`  
2. `/etc/nsswitch.conf`  
3. `/var/db/cache/group.cache` (if `nscd` is running)  

> The group cache file is used by the Name Service Cache Daemon (nscd). If caching is enabled, group lookups may access this file instead of `/etc/group`.  

The service should only be allowed to perform `fstat`, `fstatat`, and `lseek` system calls.  
All other system calls should be restricted.  

### NetDB  
This service should only be allowed to open:  
1. `/etc/nsswitch.conf`  
2. `/etc/protocols`  

It should be restricted to using only the `ioctl` and `open` system calls.  
All other system calls should be restricted.  

### Password (Pwd)  
This service should only be allowed to open:  
1. `/etc/nsswitch.conf`  
2. `/etc/spwd.db`  
3. `/etc/pwd.db`  

It should only use the following system calls:  
- `getuid`  
- `geteuid`  
- `getlogin`  
- `fstat`  
- `ioctl`  

All other system calls should be restricted.  

### Sysctl  
This service should only be allowed to open `/etc/pwd.db`.  
It should only be permitted to use the `fstat`, `ioctl`, and `open` system calls.  
All other system calls should be restricted.  

### Syslog  
This service should only be allowed to open:  
1. `/etc/localtime`  
2. `/etc/pwd.db`  

It should only use the following system calls:  
- `socket`  
- `connect`  
- `sendto`  

All other system calls should be restricted.  
