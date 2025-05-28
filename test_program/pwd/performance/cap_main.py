import subprocess
import numpy as np

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

def main():
    iterations = 50
    functions = [
        "cap_getpwnam", "cap_getpwnam_r",
        "cap_getpwuid", "cap_getpwuid_r",
        "cap_getpwent", "cap_getpwent_r"
    ]
    results = {f: [] for f in functions}

    for i in range(iterations):
        print(f"\nRunning iteration {i + 1} of casper_pwd_perf...")
        output = run_program(["cpuset", "-l", "0", "./casper_pwd_perf"])
        times = parse_times(output)
        for f in functions:
            if f in times:
                results[f].append(times[f])

    print("\nAveraged Execution Times (Filtered):")
    for f in functions:
        values = np.array(results[f])
        if len(values) > 2:
            lower = np.percentile(values, 5)
            upper = np.percentile(values, 95)
            values = values[(values >= lower) & (values <= upper)]
        avg = values.mean() if len(values) > 0 else float('nan')
        print(f"{f}: {avg:.6f} seconds")

if __name__ == "__main__":
    main()
