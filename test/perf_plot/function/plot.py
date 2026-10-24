import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np


RESULTS_PATH = Path(__file__).with_name("test_results.json")


def plot_architecture(architecture, scenarios):
    baseline = scenarios["baseline"]
    with_mac = scenarios["with_mac"]
    baseline_results = baseline["results"]
    mac_results = with_mac["results"]
    services = [
        service
        for service in baseline_results
        if service in mac_results
        and set(baseline_results[service]) & set(mac_results[service])
    ]
    if not services:
        print(f"[WARN] No comparable function results for {architecture}; skipping.")
        return

    rows = (len(services) + 1) // 2
    fig, axes = plt.subplots(rows, 2, figsize=(16, max(6, rows * 4)), squeeze=False)
    flat_axes = axes.flatten()

    for index, service in enumerate(services):
        ax = flat_axes[index]
        functions = [
            name
            for name in baseline_results[service]
            if name in mac_results[service]
        ]
        base_values = np.array([baseline_results[service][name] for name in functions])
        mac_values = np.array([mac_results[service][name] for name in functions])
        positions = np.arange(len(functions))
        height = 0.35

        ax.barh(
            positions + height / 2,
            base_values,
            height,
            label="Baseline",
            color="steelblue",
        )
        ax.barh(
            positions - height / 2,
            mac_values,
            height,
            label="With MAC",
            color="darkorange",
        )

        for position, base_value, mac_value in zip(positions, base_values, mac_values):
            if base_value > 0:
                overhead = (mac_value - base_value) / base_value * 100
                ax.text(
                    mac_value * 1.02,
                    position - height / 2,
                    f"{overhead:+.1f}%",
                    ha="left",
                    va="center",
                    fontsize=9,
                )

        ax.set_title(service.replace("_", " ").title())
        ax.set_yticks(positions)
        ax.set_yticklabels(functions)
        ax.invert_yaxis()
        max_value = max(float(base_values.max()), float(mac_values.max()))
        ax.set_xlim(0, max_value * 1.25 if max_value else 1)
        ax.grid(axis="x", linestyle="--", alpha=0.5)

    for ax in flat_axes[len(services):]:
        ax.axis("off")

    handles, labels = flat_axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper right")
    fig.suptitle(
        f"{architecture.upper()} Function Performance "
        f"(Python iterations: baseline {baseline['iterations']}, "
        f"with MAC {with_mac['iterations']})",
        fontsize=16,
    )
    fig.supxlabel("Execution time (seconds)")
    fig.tight_layout(rect=[0, 0.03, 1, 0.93])
    output_path = Path(f"function_performance_{architecture}.png")
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Generated {output_path}")


def main():
    with RESULTS_PATH.open("r", encoding="utf-8") as result_file:
        data = json.load(result_file)
    if data.get("schema_version") != 1:
        raise ValueError(f"Unsupported results format in {RESULTS_PATH}")

    for architecture, scenarios in data.get("runs", {}).items():
        if not {"baseline", "with_mac"}.issubset(scenarios):
            print(f"[INFO] {architecture}: run both scenarios before plotting.")
            continue
        plot_architecture(architecture, scenarios)


if __name__ == "__main__":
    main()
