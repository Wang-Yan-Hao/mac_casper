#!/usr/bin/env python3
import os
import numpy as np
from scipy.stats import gaussian_kde
import warnings

warnings.filterwarnings("ignore")

def get_kde_mode(data):
    if len(data) < 2:
        return np.mean(data) if len(data) == 1 else 0

    try:
        kernel = gaussian_kde(data)

        x_min, x_max = np.min(data), np.max(data)
        x_range = np.linspace(x_min * 0.9, x_max * 1.1, 1000)

        kde_values = kernel(x_range)
        mode_val = x_range[np.argmax(kde_values)]
        return mode_val
    except:
        return np.mean(data)

def load_perf_data(file_path):
    if not os.path.exists(file_path):
        return None
    try:
        data = np.loadtxt(file_path)
        # Remove first 5 data
        if len(data) > 10:
            return data[5:]
        return data
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return None

def run_analysis():
    folders = ['md5', 'wc', 'sockstat', 'kdump', 'ping', 'logger']

    print(f"{'Command':<12} | {'Metric':<10} | {'Base (s)':<10} | {'Exp (s)':<10} | {'Overhead':<10}")
    print("-" * 65)

    for cmd in folders:
        base_file = os.path.join(cmd, f"{cmd}_base.txt")
        exp_file = os.path.join(cmd, f"{cmd}_exp.txt")

        base_data = load_perf_data(base_file)
        exp_data = load_perf_data(exp_file)

        if base_data is None or exp_data is None:
            continue

        b_mean = np.mean(base_data)
        e_mean = np.mean(exp_data)

        b_mode = get_kde_mode(base_data)
        e_mode = get_kde_mode(exp_data)

        overhead_mode = ((e_mode - b_mode) / b_mode) * 100
        overhead_mean = ((e_mean - b_mean) / b_mean) * 100

        print(f"{cmd:<12} | {'KDE Mode':<10} | {b_mode:<10.4f} | {e_mode:<10.4f} | {overhead_mode:>+7.2f}%")
        print(f"{'':<12} | {'Mean':<10} | {b_mean:<10.4f} | {e_mean:<10.4f} | {overhead_mean:>+7.2f}%")
        print("-" * 65)

if __name__ == "__main__":
    run_analysis()
