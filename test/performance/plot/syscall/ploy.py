import json
import matplotlib.pyplot as plt
import numpy as np
import matplotlib

matplotlib.use('Agg')

def plot_performance(json_file):
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {json_file} not found.")
        return

    archs = ['arm64', 'amd64']
    ops = ['open', 'socket', 'sysctl']
    op_titles = ['open("/etc/hosts") + close()', 'socket(AF_INET) + close()', 'sysctl']

    fig, axes = plt.subplots(3, 2, figsize=(16, 19))

    for row, op in enumerate(ops):
        for col, arch in enumerate(archs):
            ax = axes[row, col]
            arch_data = data[arch]
            labels = arch_data['labels']
            values = arch_data[op]

            color_map = matplotlib.colormaps['tab10']
            bars = ax.bar(labels, values, edgecolor='black', alpha=0.85)

            ax.set_ylim(0, max(values) * 1.2)

            ax.set_title(f"{arch.upper()} - {op_titles[row]}", fontsize=16, fontweight='bold')
            ax.set_ylabel("Latency (seconds)", fontsize=13)
            ax.tick_params(axis='x', labelsize=13)
            ax.grid(axis='y', linestyle='--', alpha=0.5)

            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + (max(values)*0.01),
                        f'{height:.3f}', ha='center', va='bottom', fontsize=11, fontweight='bold')

            c_iter = arch_data['c_iters'][op]
            py_iter = data['common']['py_iter']
            ax.text(0.98, 0.98, f'C Iter: {c_iter}\nPy Iter: {py_iter}',
                    transform=ax.transAxes, ha='right', va='top', fontsize=11,
                    bbox=dict(boxstyle="round,pad=0.3", facecolor="white", edgecolor="gray", alpha=0.8))

    plt.tight_layout(rect=[0, 0.03, 1, 0.96])
    output_name = "casper_syscall_eval.png"
    plt.savefig(output_name, dpi=300, bbox_inches='tight')
    print(f"Successfully generated: {output_name}")

if __name__ == "__main__":
    plot_performance('data.json')

