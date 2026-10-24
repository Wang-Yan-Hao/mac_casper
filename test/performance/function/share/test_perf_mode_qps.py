import sys
from pathlib import Path

import numpy as np
from scipy.stats import gaussian_kde
import matplotlib
if "--save-plot" in sys.argv:
    matplotlib.use("Agg")

import matplotlib.pyplot as plt

from config import CASPER_CONFIG_QPS, run_program, parse_qps
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from results import SCENARIOS, save_results

SHOW_PLOTS = "off"

def run_benchmark(service):
    config = CASPER_CONFIG_QPS.get(service)
    if config is None:
        print(f"[ERROR] Unknown service '{service}'")
        return

    binary = config["binary"]
    functions = config["functions"]
    needs_input = config["needs_input"]

    print(f"\n=== Benchmarking {service.upper()} ===")
    results = {f: [] for f in functions}

    cmd = ["cpuset", "-l", "0", binary]
    if needs_input:
        cmd.append(config["input_file"])

    output = run_program(cmd)
    times = parse_qps(output)
    for f in functions:
        if f in times:
            results[f].append(times[f])

    print(f"\n--- Results for service '{service}' ---")
    service_results = {}
    for f in functions:
        samples = [sample for batch in results[f] for sample in batch]
        values = np.array(samples)
        if len(values) == 0:
            print(f"{f}: No data")
            continue

        if len(values) < 2 or np.all(values == values[0]):
            kde_peak_val = values.mean()
            mode_avg = kde_peak_val
            x_grid = np.linspace(values.min(), values.max(), 1000)
            y_grid = np.zeros_like(x_grid)
        else:
            kde = gaussian_kde(values)
            x_grid = np.linspace(values.min(), values.max(), 1000)
            y_grid = kde(x_grid)
            kde_peak_val = x_grid[np.argmax(y_grid)]
            mode_nearby = values[np.isclose(values, kde_peak_val, atol=0.0005)]
            if len(mode_nearby) == 0:
                mode_nearby = values[[np.argmin(np.abs(values - kde_peak_val))]]
            mode_avg = mode_nearby.mean()
        service_results[f] = float(mode_avg)

        print(f"{f}: KDE mode = {kde_peak_val:.6f}, avg around peak = {mode_avg:.6f}")

        if SHOW_PLOTS in ("show", "save"):
            plt.figure(figsize=(8, 4))
            plt.hist(values, bins=20, density=True, alpha=0.4, color='lightgray', edgecolor='black', label='Histogram')
            plt.plot(x_grid, y_grid, color='blue', label='KDE')
            plt.axvline(kde_peak_val, color='red', linestyle='--', label=f"KDE Mode: {kde_peak_val:.6f}")
            plt.title(f"{service.upper()} - {f}")
            plt.xlabel("Execution Time (sec)")
            plt.ylabel("Density")
            plt.legend()
            plt.grid(True)
            plt.tight_layout()

            filename = f"{service}_{f}_kde.png"
            if SHOW_PLOTS == "save":
                plt.savefig(filename)
                print(f"[INFO] Plot saved: {filename}")
            elif SHOW_PLOTS == "show":
                plt.show()

            plt.close()
    return service_results

def print_usage():
    print("Usage: python3 test_perf_mode_qps.py --scenario baseline|with_mac [services] [--plot | --save-plot]")
    print("Options:")
    print("  --scenario      Required: baseline or with_mac")
    print("  --plot          Show KDE + histogram plots")
    print("  --save-plot     Save KDE + histogram plots as PNG files")
    print("  -h, --help      Show this help message and exit")
    print("Examples:")
    print("  python3 test_perf_mode_qps.py --scenario with_mac dns --save-plot")
    print("  python3 test_perf_mode_qps.py --scenario baseline")

def main():
    global SHOW_PLOTS

    args = sys.argv[1:]
    service_to_run = []
    scenario = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-h", "--help"):
            print_usage()
            sys.exit(0)
        elif arg == "--scenario" and i + 1 < len(args):
            scenario = args[i + 1]
            i += 2
            continue
        elif arg == "--plot":
            SHOW_PLOTS = "show"
        elif arg == "--save-plot":
            matplotlib.use("Agg")
            SHOW_PLOTS = "save"
        elif arg.startswith("-"):
            print(f"[ERROR] Unknown or incomplete option: {arg}")
            sys.exit(2)
        else:
            service_to_run.append(arg)
        i += 1

    if not service_to_run:
        service_to_run = list(CASPER_CONFIG_QPS.keys())

    if scenario not in SCENARIOS:
        print_usage()
        print(f"[ERROR] --scenario must be one of: {', '.join(SCENARIOS)}")
        sys.exit(2)

    all_results = {}
    for service in service_to_run:
        if service not in CASPER_CONFIG_QPS:
            print(f"[ERROR] Unknown service '{service}'")
            sys.exit(2)
        service_results = run_benchmark(service)
        if service_results:
            all_results[service] = service_results

    if all_results:
        save_results("qps", scenario, 1, all_results)
    else:
        print("[ERROR] No QPS benchmark results were collected.")
        sys.exit(1)

if __name__ == "__main__":
    main()
