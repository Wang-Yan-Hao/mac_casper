import sys
from pathlib import Path
import numpy as np
import subprocess
from scipy.stats import gaussian_kde
from config import TEST_CATEGORIES, LABELS, get_binary_path, run_program, parse_times, DEFAULT_ITERATIONS
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from results import SCENARIOS, save_results

def run_benchmark(category, label, iterations):
    binary = get_binary_path(category, label)

    if not binary.exists():
        return None

    target_label = label.strip().lower()

    results = []
    for _ in range(iterations):
        cmd = ["cpuset", "-l", "0", binary]

        output = run_program(cmd)
        times = parse_times(output)

        if target_label in times:
            results.append(times[target_label])

    if not results:
        return None

    values = np.array(results)
    if len(values) < 2 or np.all(values == values[0]):
        return float(np.mean(values))

    try:
        kde = gaussian_kde(values)
        x_grid = np.linspace(values.min(), values.max(), 1000)
        y_grid = kde(x_grid)
        kde_peak_val = x_grid[np.argmax(y_grid)]
        return float(kde_peak_val)
    except np.linalg.LinAlgError:
        return float(np.mean(values))

def main():
    args = sys.argv[1:]
    if args in (["-h"], ["--help"]):
        print(f"Usage: python3 {Path(__file__).name} --scenario baseline|with_mac")
        print(f"Runs {DEFAULT_ITERATIONS} samples per syscall/label and saves JSON results.")
        return
    if len(args) != 2 or args[0] != "--scenario" or args[1] not in SCENARIOS:
        print(f"Usage: python3 {Path(__file__).name} --scenario baseline|with_mac")
        sys.exit(2)
    scenario = args[1]

    build_script = Path(__file__).with_name("build_all.sh")
    print("[*] Rebuilding binaries via build_all.sh...")
    try:
        subprocess.run(["sh", str(build_script)], cwd=build_script.parent, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as error:
        print(f"[ERROR] Build failed: {error}")
        sys.exit(1)

    iterations = DEFAULT_ITERATIONS
    print(f"Running {iterations} sampling iterations per test...")
    print(f"{'Category':<10} | {'Label':<10} | {'Total Time (s)':<15}")
    print("-" * 45)

    all_results = {category: {} for category in TEST_CATEGORIES}
    for cat in TEST_CATEGORIES:
        for lbl in LABELS:
            mode_val = run_benchmark(cat, lbl, iterations)
            if mode_val is not None:
                print(f"{cat:<10} | {lbl:<10} | {mode_val:15.4f}")
                all_results[cat][lbl] = mode_val
            else:
                print(f"{cat:<10} | {lbl:<10} | {'N/A':<15}")

    if any(all_results.values()):
        save_results("syscall", scenario, iterations, all_results)
    else:
        print("[ERROR] No benchmark results were collected.")
        sys.exit(1)
if __name__ == "__main__":
    main()
