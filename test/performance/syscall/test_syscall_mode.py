import sys
import os
import numpy as np
import subprocess
from scipy.stats import gaussian_kde
from config import TEST_CATEGORIES, LABELS, get_binary_path, run_program, parse_times, DEFAULT_ITERATIONS

def run_benchmark(category, label, iterations):
    binary = get_binary_path(category, label)

    if not os.path.exists(binary):
        return None

    target_label = label.strip().lower()

    results = []
    for _ in range(iterations):
        cmd = ["cpuset", "-l", "0", binary]

        output = run_program(cmd)
        times = parse_times(output)

        if target_label in times:
            results.append(times[target_label])

    if len(results) < 2:
        return None

    try:
        values = np.array(results)
        kde = gaussian_kde(values)
        x_grid = np.linspace(values.min(), values.max(), 1000)
        y_grid = kde(x_grid)
        kde_peak_val = x_grid[np.argmax(y_grid)]
        return kde_peak_val
    except Exception:
        return np.mean(values)

def main():
    print("[*] Rebuilding binaries via build_all.sh...")
    try:
        subprocess.run(["sh", "./build_all.sh"], check=True)
        print("[*] Build successful.\n")
    except Exception as e:
        print(f"[ERROR] Build failed: {e}")
        sys.exit(1)

    iterations = DEFAULT_ITERATIONS
    print(f"Running {iterations} sampling iterations per test...")
    print(f"{'Category':<10} | {'Label':<10} | {'Total Time (s)':<15}")
    print("-" * 45)

    for cat in TEST_CATEGORIES:
        for lbl in LABELS:
            mode_val = run_benchmark(cat, lbl, iterations)
            if mode_val is not None:
                print(f"{cat:<10} | {lbl:<10} | {mode_val:15.4f}")
            else:
                print(f"{cat:<10} | {lbl:<10} | {'N/A':<15}")

if __name__ == "__main__":
    main()
