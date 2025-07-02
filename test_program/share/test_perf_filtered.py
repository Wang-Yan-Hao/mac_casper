import sys
import numpy as np
from config import CASPER_CONFIG, DEFAULT_ITERATIONS, run_program, parse_times

def print_usage():
    print("Usage: python3 test_perf_filter.py [services] [--iter N]")
    print("Options:")
    print("  --iter N        Run each test N times (default: 50)")
    print("  -h, --help      Show this help message and exit")
    print("Examples:")
    print("  python3 test_perf_filter.py dns --iter 100")
    print("  python3 test_perf_filter.py fileargs grp")
    print("  python3 test_perf_filter.py              # Run all services")

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
        if len(values) > 2:
            # Filter out outliers (5th to 95th percentile)
            lower = np.percentile(values, 5)
            upper = np.percentile(values, 95)
            values = values[(values >= lower) & (values <= upper)]

        avg = values.mean() if len(values) > 0 else float('nan')
        print(f"{f}: {avg:.6f} seconds")

def main():
    iterations = DEFAULT_ITERATIONS
    services_to_run = []

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-h", "--help"):
            print_usage()
            return
        elif arg == "--iter" and i + 1 < len(args):
            try:
                iterations = int(args[i + 1])
                i += 2
                continue
            except ValueError:
                print("[WARN] Invalid value for --iter; using default.")
                i += 2
                continue
        elif not arg.startswith("--"):
            services_to_run.append(arg)
        i += 1

    if not services_to_run:
        print("[INFO] No service specified. Running all services...")
        services_to_run = list(CASPER_CONFIG.keys())

    for service in services_to_run:
        run_benchmark(service, iterations)

if __name__ == "__main__":
    main()
