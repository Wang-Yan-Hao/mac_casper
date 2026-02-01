import json
import os

import matplotlib.pyplot as plt
import numpy as np

os.path.dirname(__file__)


def plot_single_arch(arch_name, data):
    services = data["common"]["services"]
    functions_list = data["common"]["functions"]
    py_iterations = data["common"]["python_iterations"]

    baseline_list = data[arch_name]["baseline"]
    with_method_list = data[arch_name]["with_method"]
    c_iterations = data[arch_name]["c_iterations"]

    fig, axes_flat = plt.subplots(4, 2, figsize=(14, 16))
    axes = axes_flat.flatten()

    max_n = max(len(f) for f in functions_list)

    for i in range(len(services)):
        ax = axes[i]
        functions = functions_list[i]
        base_vals = np.array(baseline_list[i])
        with_vals = np.array(with_method_list[i])
        n = len(functions)

        y = np.arange(n)
        height = 0.35

        ax.barh(y + height / 2, base_vals, height, label="Baseline", color="steelblue")
        ax.barh(
            y - height / 2, with_vals, height, label="With Method", color="darkorange"
        )

        for j in range(n):
            overhead = ((with_vals[j] - base_vals[j]) / base_vals[j]) * 100
            ax.text(
                with_vals[j] + (with_vals[j] * 0.02),
                y[j] - height / 2,
                f"+{overhead:.1f}%",
                ha="left",
                va="center",
                fontsize=10,
                color="darkred",
                fontweight="bold",
            )

        ax.set_title(services[i], fontsize=14, fontweight="bold")
        ax.set_yticks(y)
        ax.set_yticklabels(functions, fontsize=11)
        ax.invert_yaxis()

        diff = max_n - n
        ax.set_ylim((n - 0.5) + (diff / 2), -0.5 - (diff / 2))

        ax.set_xlim(0, max(max(base_vals), max(with_vals)) * 1.2)

        iter_text = f"C: {c_iterations[i]}\nPython: {py_iterations[i]}"
        ax.text(
            0.98,
            1.12,
            iter_text,
            transform=ax.transAxes,
            ha="right",
            va="top",
            fontsize=10,
            color="black",
            bbox=dict(
                boxstyle="round,pad=0.2",
                facecolor="white",
                alpha=0.7,
                edgecolor="lightgray",
            ),
        )

    for j in range(len(services), len(axes)):
        axes[j].axis("off")

    handles, labels = ax.get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="upper right", bbox_to_anchor=(1, 1.015), fontsize=12
    )

    fig.text(
        0.5,
        0.01,
        "x-axis: Time (second), y-axis: Function names.\nPercentages indicate overhead compared to Baseline.",
        ha="center",
        fontsize=14,
        fontweight="bold",
        style="italic",
        bbox=dict(facecolor="none", edgecolor="black", pad=5.0),
    )

    plt.tight_layout(rect=[0, 0.04, 1, 0.97], h_pad=2)
    filename = f"function_performance_{arch_name}.png"
    plt.savefig(filename, dpi=300, bbox_inches="tight")
    print(f"Generate {filename}")
    plt.close()


with open("data.json", "r") as f:
    full_data = json.load(f)

for arch in ["amd64", "arm64"]:
    plot_single_arch(arch, full_data)
