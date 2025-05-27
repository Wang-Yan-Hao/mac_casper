import subprocess
import numpy as np

def run_program(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def parse_time(output, keyword="cap_getprotobyname"):
    for line in output.splitlines():
        if line.startswith(keyword) and "took" in line:
            parts = line.split()
            try:
                return float(parts[2])
            except (ValueError, IndexError):
                continue
    return None

def main():
    iterations = 50
    results = []

    for i in range(iterations):
        print(f"Running iteration {i + 1} of casper_netdb_perf...")
        output = run_program(["cpuset", "-l", "0", "./casper_netdb_perf"])
        print(output.strip())
        t = parse_time(output)
        if t is not None:
            results.append(t)

    print("\nAveraged Execution Time (Filtered):")
    values = np.array(results)
    if len(values) > 2:
        lower = np.percentile(values, 5)
        upper = np.percentile(values, 95)
        values = values[(values >= lower) & (values <= upper)]
    avg = values.mean() if len(values) > 0 else float('nan')
    print(f"cap_getprotobyname: {avg:.6f} seconds")

if __name__ == "__main__":
    main()
