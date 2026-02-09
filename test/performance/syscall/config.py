import subprocess
import os

TEST_CATEGORIES = ["open", "socket", "sysctl"]
LABELS = ["baseline", "dns", "fileargs", "grp", "netdb", "pwd", "sysctl", "syslog"]

DEFAULT_ITERATIONS = 50

def get_binary_path(category, label):
    return os.path.join(category, f"perf_{label}")

def run_program(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return ""

def parse_times(output):
    times = {}
    if not output: return times

    for line in output.splitlines():
        if "|" in line and "total:" in line.lower():
            parts = line.split("|")
            label = parts[0].replace(" ", "").strip().lower()

            try:
                total_val = float(parts[1].split(":")[1].strip().split()[0])
                times[label] = total_val
            except (IndexError, ValueError):
                continue
    return times
