#!/usr/bin/env python3
"""
3D Performance Comparison of Hybrid Post-Quantum Protocols.

Renders a grouped 3-D bar chart where one horizontal axis lists protocols,
the other lists performance metrics (message size, computation time,
round-trips), and the vertical axis shows normalised values for easy
visual comparison.

Output: performance_3d.png (300 dpi), performance_3d.svg
"""

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D  # noqa: F401
import os

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Raw data
# ---------------------------------------------------------------------------
protocols = [
    "Classic\nOPAQUE",
    "Hybrid\nPQ-OPAQUE",
    "TLS 1.3\nHybrid",
    "Signal\nPQXDH",
    "WireGuard\nPQ",
]

metrics = [
    "Розмір повідомлень\n(байти)",
    "Час обчислень\n(мс)",
    "Кількість\nзворотних шляхів",
]

# Raw values: rows = protocols, cols = metrics
#                    msg_bytes  comp_ms  round_trips
raw = np.array([
    [   576,    0.8,    2],   # Classic OPAQUE
    [  3424,    3.2,    2],   # Hybrid PQ-OPAQUE (ML-KEM-768)
    [  2900,    2.1,    1],   # TLS 1.3 Hybrid
    [  3168,    2.8,    3],   # Signal PQXDH
    [  2560,    1.9,    1],   # WireGuard PQ
], dtype=float)

# Normalise each metric column to [0, 1] for visual comparison
maxvals = raw.max(axis=0)
norm = raw / maxvals

n_protocols = len(protocols)
n_metrics = len(metrics)

# ---------------------------------------------------------------------------
# Build bar positions
# ---------------------------------------------------------------------------
bar_width = 0.55
bar_depth = 0.55

xpos = np.arange(n_protocols)
ypos = np.arange(n_metrics)

# Color palette (one per metric)
metric_colors = ["#1e88e5", "#43a047", "#fb8c00"]
metric_edge   = ["#0d47a1", "#1b5e20", "#e65100"]

# ---------------------------------------------------------------------------
# Figure
# ---------------------------------------------------------------------------
fig = plt.figure(figsize=(15, 10), facecolor="white")
ax = fig.add_subplot(111, projection="3d")

for mi in range(n_metrics):
    xs = xpos
    ys = np.full(n_protocols, mi)
    zs = np.zeros(n_protocols)
    dx = np.full(n_protocols, bar_width)
    dy = np.full(n_protocols, bar_depth)
    dz = norm[:, mi]

    ax.bar3d(
        xs, ys, zs, dx, dy, dz,
        color=metric_colors[mi], edgecolor=metric_edge[mi],
        alpha=0.82, linewidth=0.5, zsort="average",
        label=metrics[mi].replace("\n", " "),
    )

    # Value annotations on top of each bar
    for pi in range(n_protocols):
        val = raw[pi, mi]
        if mi == 2:
            txt = f"{int(val)}"
        elif mi == 1:
            txt = f"{val:.1f} мс"
        else:
            txt = f"{int(val)} Б"
        ax.text(
            xpos[pi] + bar_width / 2,
            mi + bar_depth / 2,
            norm[pi, mi] + 0.03,
            txt,
            ha="center", va="bottom", fontsize=7.5,
            color="#212121", fontweight="bold",
        )

# ---------------------------------------------------------------------------
# Axes ticks and labels
# ---------------------------------------------------------------------------
ax.set_xticks(xpos + bar_width / 2)
ax.set_xticklabels(protocols, fontsize=8.5, ha="center")
ax.set_yticks(ypos + bar_depth / 2)
ax.set_yticklabels(metrics, fontsize=8.5)
ax.set_zlabel("Нормалізоване значення", fontsize=11, labelpad=12)
ax.set_zlim(0, 1.25)

ax.set_title(
    "Порівняння продуктивності гібридних протоколів",
    fontsize=16, fontweight="bold", pad=22,
)

# Viewing angle
ax.view_init(elev=25, azim=-55)

# Legend
ax.legend(
    loc="upper left", fontsize=9, framealpha=0.9,
    edgecolor="#bdbdbd", borderpad=1.0, labelspacing=0.8,
)

# Annotation with raw ranges
note = (
    "Нормалізація: кожна метрика масштабована\n"
    f"до max = 1.0   (макс. байти={int(maxvals[0])},\n"
    f"макс. час={maxvals[1]:.1f} мс, макс. RT={int(maxvals[2])})"
)
props = dict(boxstyle="round,pad=0.5", facecolor="#e8f5e9", alpha=0.9, edgecolor="#66bb6a")
ax.text2D(
    0.68, 0.18, note, transform=ax.transAxes,
    fontsize=8.5, verticalalignment="top", bbox=props,
)

plt.tight_layout()

# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------
png_path = os.path.join(OUTPUT_DIR, "performance_3d.png")
svg_path = os.path.join(OUTPUT_DIR, "performance_3d.svg")
fig.savefig(png_path, dpi=300, bbox_inches="tight", facecolor="white")
fig.savefig(svg_path, format="svg", bbox_inches="tight", facecolor="white")
plt.close(fig)

print(f"Saved: {png_path}")
print(f"Saved: {svg_path}")
