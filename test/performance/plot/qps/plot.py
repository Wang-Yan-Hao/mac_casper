import json
import os

import matplotlib.pyplot as plt
import numpy as np

os.path.dirname(__file__)

with open("qps.json", "r") as f:
    data = json.load(f)

functions = data["functions"]
arm_base = data["arm64"]["baseline"]
arm_with = data["arm64"]["with_mac"]
amd_base = data["amd64"]["baseline"]
amd_with = data["amd64"]["with_mac"]

all_vals = arm_base + arm_with + amd_base + amd_with
max_val = max(all_vals)

x = np.arange(len(functions))
width = 0.22

fig, ax = plt.subplots(figsize=(14, 7))
ax.set_ylim(0, max_val * 1.1)

bars1 = ax.bar(
    x - 1.5 * width,
    arm_base,
    width,
    label="ARM64 Baseline",
    color="steelblue",
    alpha=0.9,
)
bars2 = ax.bar(
    x - 0.5 * width,
    arm_with,
    width,
    label="ARM64 With MAC",
    color="darkorange",
    alpha=0.9,
)
bars3 = ax.bar(
    x + 0.5 * width, amd_base, width, label="AMD64 Baseline", color="#2ca02c", alpha=0.9
)
bars4 = ax.bar(
    x + 1.5 * width,
    amd_with,
    width,
    label="AMD64 With MAC",
    color="#d62728",
    alpha=0.9,
)

ax.set_xticks(x)
ax.set_xticklabels(functions, ha="center", fontsize=16)
ax.set_ylabel("Queries Per Second (QPS)", fontsize=17, fontweight="bold")


def autolabel(rects):
    for rect in rects:
        height = int(rect.get_height())
        ax.annotate(
            f"{height}",
            xy=(rect.get_x() + rect.get_width() / 2, height),
            xytext=(0, 5),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=15,
            rotation=25
        )


for b in [bars1, bars2, bars3, bars4]:
    autolabel(b)

ax.legend(loc="upper left", fontsize=17, frameon=True, shadow=True)
ax.grid(axis="y", linestyle="--", alpha=0.6)

plt.tight_layout()
plt.savefig("qps_comparison.png", dpi=300)
print("Successfully generated qps_comparison.png from qps.json")
