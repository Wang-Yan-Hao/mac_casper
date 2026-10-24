import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt


RESULTS_PATH = Path(__file__).with_name("test_results.json")
CATEGORIES = ("open", "socket", "sysctl")


def main():
    with RESULTS_PATH.open("r", encoding="utf-8") as result_file:
        data = json.load(result_file)
    if data.get("schema_version") != 1:
        raise ValueError(f"Unsupported results format in {RESULTS_PATH}")

    runs = [
        (architecture, scenario, run)
        for architecture, scenarios in data.get("runs", {}).items()
        for scenario, run in scenarios.items()
    ]
    if not runs:
        raise ValueError(f"No syscall results found in {RESULTS_PATH}")

    fig, axes = plt.subplots(
        len(CATEGORIES),
        len(runs),
        figsize=(max(8, 7 * len(runs)), 18),
        squeeze=False,
    )
    for column, (architecture, scenario, run) in enumerate(runs):
        for row, category in enumerate(CATEGORIES):
            ax = axes[row, column]
            values = run["results"].get(category, {})
            labels = list(values)
            measurements = list(values.values())
            if not labels:
                ax.set_axis_off()
                continue

            bars = ax.bar(labels, measurements, edgecolor="black", alpha=0.85)
            ax.set_ylim(0, max(measurements) * 1.2 if max(measurements) else 1)
            ax.set_title(
                f"{architecture.upper()} {scenario.replace('_', ' ').title()}\n{category}"
            )
            ax.set_ylabel("Total time (seconds)")
            ax.tick_params(axis="x", labelrotation=45)
            ax.grid(axis="y", linestyle="--", alpha=0.5)

            padding = max(measurements) * 0.01
            for bar in bars:
                height = bar.get_height()
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    height + padding,
                    f"{height:.3f}",
                    ha="center",
                    va="bottom",
                    fontsize=8,
                )

    fig.suptitle("Syscall Benchmark Results", fontsize=16)
    fig.tight_layout(rect=[0, 0, 1, 0.97])
    output_path = Path("casper_syscall_eval.png")
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Generated {output_path}")


if __name__ == "__main__":
    main()
