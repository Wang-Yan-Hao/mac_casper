# test_perf_mode.py
import sys
import numpy as np
from scipy.stats import gaussian_kde
import matplotlib
import matplotlib.pyplot as plt

from config import CASPER_CONFIG, DEFAULT_ITERATIONS, run_program, parse_times

SHOW_PLOTS = "off"

def run_benchmark(service, iterations):
    config = CASPER_CONFIG.get(service)
    if config is None:
        print(f"[ERROR] Unknown service '{service}'")
        return

    binary = config["binary"]
    functions = config["functions"]
    needs_input = config["needs_input"]

    print(f"\n=== Benchmarking {service.upper()} ({iterations} iterations) ===")
    results = {f: [] for f in functions}

    for i in range(iterations):
        print(f"  Running iteration {i + 1}...")
        cmd = ["cpuset", "-l", "0", binary]
        if needs_input:
            cmd.append(config["input_file"])

        output = run_program(cmd)
        times = parse_times(output)
        for f in functions:
            if f in times:
                results[f].append(times[f])

    print(f"\n--- Results for service '{service}' ---")
    for f in functions:
        values = np.array(results[f])
        if len(values) == 0:
            print(f"{f}: No data")
            continue

        kde = gaussian_kde(values)
        x_grid = np.linspace(values.min(), values.max(), 1000)
        y_grid = kde(x_grid)
        kde_peak_val = x_grid[np.argmax(y_grid)]
        mode_nearby = values[np.isclose(values, kde_peak_val, atol=0.0005)]
        mode_avg = mode_nearby.mean()

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

def print_usage():
    print("Usage: python3 test_perf_mode.py [services] [--iter N] [--plot | --save-plot]")
    print("Options:")
    print("  --iter N        Run each test N times (default: 50)")
    print("  --plot          Show KDE + histogram plots")
    print("  --save-plot     Save KDE + histogram plots as PNG files")
    print("  -h, --help      Show this help message and exit")
    print("Examples:")
    print("  python3 test_perf_mode.py fileargs --iter 100 --save-plot")
    print("  python3 test_perf_mode.py dns grp")
    print("  python3 test_perf_mode.py              # Run all services")

def main():
    global SHOW_PLOTS

    args = sys.argv[1:]
    iterations = DEFAULT_ITERATIONS
    service_to_run = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-h", "--help"):
            print_usage()
            sys.exit(0)
        elif arg == "--iter" and i + 1 < len(args):
            try:
                iterations = int(args[i + 1])
                i += 2
                continue
            except ValueError:
                i += 2
                continue
        elif arg == "--plot":
            SHOW_PLOTS = "show"
        elif arg == "--save-plot":
            matplotlib.use("Agg")
            SHOW_PLOTS = "save"
        elif not arg.startswith("--"):
            service_to_run.append(arg)
        i += 1

    if not service_to_run:
        service_to_run = list(CASPER_CONFIG.keys())

    for service in service_to_run:
        run_benchmark(service, iterations)

if __name__ == "__main__":
    main()
