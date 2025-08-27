# config.py
import subprocess

# Global default
DEFAULT_ITERATIONS = 50
SHOW_PLOTS = "off"

CASPER_CONFIG = {
    "dns": {
        "functions": [
            "getaddrinfo",
            "getnameinfo",
            "gethostbyname",
            "gethostbyname2",
            "gethostbyaddr"
        ],
        "needs_input": False,
        "binary": "../dns/performance/cap_dns",
    },
    "fileargs": {
        "functions": [
            "fileargs_open",
            "fileargs_lstat",
            "fileargs_realpath",
            "fileargs_fopen"
        ],
        "needs_input": True,
        "input_file": "../fileargs/performance/test1.txt",
        "binary": "../fileargs/performance/casper_fileargs_perf",
    },
    "grp": {
        "functions": [
            "cap_getgrnam",
            "cap_getgrnam_r",
            "cap_getgrgid",
            "cap_getgrgid_r",
            "cap_getgrent",
            "cap_getgrent_r"
        ],
        "needs_input": False,
        "binary": "../grp/performance/casper_grp_perf",
    },
    "netdb": {
        "functions": [
            "cap_getprotobyname"
        ],
        "needs_input": False,
        "binary": "../netdb/performance/casper_netdb_perf",
    },
    "pwd": {
        "functions": [
            "cap_getpwnam",
            "cap_getpwnam_r",
            "cap_getpwuid",
            "cap_getpwuid_r",
            "cap_getpwent",
            "cap_getpwent_r"
        ],
        "needs_input": False,
        "binary": "../pwd/performance/casper_pwd_perf",
    },
    "sysctl": {
        "functions": [
            "cap_sysctlbyname",
            "cap_sysctlnametomib",
            "cap_sysctl"
        ],
        "needs_input": False,
        "binary": "../sysctl/performance/casper_sysctl_perf",
    },
    "syslog": {
        "functions": [
            "cap_syslog",
        ],
        "needs_input": False,
        "binary": "../syslog/performance/casper_syslog_perf",
    },
}

CASPER_CONFIG_QPS = {
    "dns": {
        "functions": [
            "cap_getaddrinfo",
            "cap_getnameinfo",
            "cap_gethostbyname",
            "cap_gethostbyname2",
            "cap_gethostbyaddr"
        ],
        "needs_input": False,
        "binary": "../dns/performance/dns_qps",
    },
    "grp": {
        "functions": [
            "cap_getgrnam",
            "cap_getgrnam_r",
            "cap_getgrgid",
            "cap_getgrgid_r",
            "cap_getgrent",
            "cap_getgrent_r"
        ],
        "needs_input": False,
        "binary": "../grp/performance/casper_grp_perf",
    },
    "netdb": {
        "functions": [
            "cap_getprotobyname"
        ],
        "needs_input": False,
        "binary": "../netdb/performance/casper_netdb_perf",
    },
    "pwd": {
        "functions": [
            "cap_getpwnam",
            "cap_getpwnam_r",
            "cap_getpwuid",
            "cap_getpwuid_r",
            "cap_getpwent",
            "cap_getpwent_r"
        ],
        "needs_input": False,
        "binary": "../pwd/performance/casper_pwd_perf",
    },
}

def run_program(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def parse_times(output):
    times = {}
    for line in output.splitlines():
        if "took" in line:
            parts = line.split()
            if len(parts) >= 4:
                func = parts[0]
                try:
                    sec = float(parts[2])
                    times[func] = sec
                except ValueError:
                    continue
    return times

def parse_qps(output):
    queries = {}
    for line in output.splitlines():
        if "Second" in line:
            parts = line.split()
            if len(parts) >= 4:
                func = parts[0]
                try:
                    sec = float(parts[4])
                    if func not in queries:
                        queries[func] = []
                    queries[func].append(sec)
                except ValueError:
                    continue
    return queries
