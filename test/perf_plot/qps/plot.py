import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np


RESULTS_PATH = Path(__file__).with_name("test_results.json")
COLORS = {
    ("baseline", "amd64"): "steelblue",
    ("with_mac", "amd64"): "darkorange",
    ("baseline", "arm64"): "seagreen",
    ("with_mac", "arm64"): "firebrick",
}


def flatten_results(results):
    flattened = {}
    for service, functions in results.items():
        for function, value in functions.items():
            flattened[f"{service}.{function}"] = value
    return flattened


def main():
    with RESULTS_PATH.open("r", encoding="utf-8") as result_file:
        data = json.load(result_file)
    if data.get("schema_version") != 1:
        raise ValueError(f"Unsupported results format in {RESULTS_PATH}")

    series = []
    for architecture, scenarios in data.get("runs", {}).items():
        for scenario in ("baseline", "with_mac"):
            if scenario in scenarios:
                run = scenarios[scenario]
                series.append(
                    (
                        architecture,
                        scenario,
                        flatten_results(run["results"]),
                    )
                )
    if not series:
        raise ValueError(f"No QPS results found in {RESULTS_PATH}")

    labels = sorted({label for _, _, values in series for label in values})
    x_positions = np.arange(len(labels))
    width = 0.8 / len(series)
    fig, ax = plt.subplots(figsize=(max(12, len(labels) * 1.4), 7))

    for index, (architecture, scenario, values) in enumerate(series):
        offset = (index - (len(series) - 1) / 2) * width
        heights = [values.get(label, np.nan) for label in labels]
        bars = ax.bar(
            x_positions + offset,
            heights,
            width,
            label=f"{architecture.upper()} {scenario.replace('_', ' ').title()}",
            color=COLORS.get((scenario, architecture)),
        )
        ax.bar_label(bars, fmt="%.0f", padding=3, fontsize=8)

    ax.set_xticks(x_positions)
    ax.set_xticklabels(labels, rotation=35, ha="right")
    ax.set_ylabel("Queries per second")
    ax.set_title("DNS QPS by Architecture and Scenario")
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.6)
    fig.tight_layout()

    output_path = Path("qps_comparison.png")
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Generated {output_path}")


if __name__ == "__main__":
    main()
