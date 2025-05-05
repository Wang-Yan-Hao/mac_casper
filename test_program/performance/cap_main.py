import subprocess
import numpy as np

def run_program(cmd):
    # Set CPU affinity using cpuset, limiting to a specific core
    process = subprocess.run(cmd, capture_output=True, text=True)
    return process.stdout

def parse_times(output):
    times = {}
    for line in output.split("\n"):
        if "took" in line:
            parts = line.split()
            function_name = parts[0]  # Get the full function name without slicing
            time_taken = float(parts[2])
            times[function_name] = time_taken
    return times

def get_filtered_average(values):
    values = np.array(values)
    if len(values) > 2:  # Ensure there are enough values to filter
        lower_bound = np.percentile(values, 5)  # Remove bottom 5%
        upper_bound = np.percentile(values, 95)  # Remove top 5%
        filtered_values = values[(values >= lower_bound) & (values <= upper_bound)]

        if len(filtered_values) > 0:
            return np.mean(filtered_values)
    return np.mean(values)  # If filtering doesn't work, return the mean of all values

def main():
    iterations = 200
    results_origin = {"getaddrinfo": [], "getnameinfo": [], "gethostbyname": [], "gethostbyname2": [], "gethostbyaddr": []}
    results_origin_mac = {"getaddrinfo": [], "getnameinfo": [], "gethostbyname": [], "gethostbyname2": [], "gethostbyaddr": []}

    for _ in range(iterations):
        print("Running dns_origin...")
        output1 = run_program(["cpuset", "-l", "0", "./dns_origin"])
        times1 = parse_times(output1)

        for key in results_origin:
            if key in times1:
                results_origin[key].append(times1[key])

        print("Running dns_origin_mac...")
        output2 = run_program(["cpuset", "-l", "0", "./cap_dns"])
        times2 = parse_times(output2)
        for key in results_origin_mac:
            if key in times2:
                results_origin_mac[key].append(times2[key])

    print("\nFinal Comparison of Execution Times:")
    for key in results_origin:
        avg_origin = get_filtered_average(results_origin[key])
        avg_origin_mac = get_filtered_average(results_origin_mac[key])

        # Avoid division by zero for percent_diff calculation
        if avg_origin != 0:
            diff = avg_origin_mac - avg_origin
            percent_diff = (diff / avg_origin) * 100
        else:
            diff = 0
            percent_diff = 0

        print(f"{key}: {avg_origin:.6f} sec vs {avg_origin_mac:.6f} sec (diff: {diff:.6f} sec, {percent_diff:.2f}%)")

if __name__ == "__main__":
    main()
