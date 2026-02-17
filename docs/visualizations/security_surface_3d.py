#!/usr/bin/env python3
"""
3D Security Parameter Comparison Surface for Hybrid PQ-OPAQUE.

Plots protocols in a 3-D space of (classical security bits, quantum security
bits, total key-exchange overhead in bytes) and fits an interpolated surface
to convey the security-vs-cost trade-off.

Output: security_surface_3d.png (300 dpi), security_surface_3d.svg
"""

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D  # noqa: F401
from matplotlib import cm
from scipy.interpolate import griddata
import os

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Protocol data
# (classical_bits, quantum_bits, overhead_bytes)
# ---------------------------------------------------------------------------
protocols = {
    "Classic OPAQUE\n(X25519)": {
        "classical": 128,
        "quantum": 0,
        "overhead": 576,
        "color": "#e53935",
        "marker": "o",
    },
    "Hybrid PQ-OPAQUE\n(ML-KEM-512)": {
        "classical": 128,
        "quantum": 128,
        "overhead": 2384,
        "color": "#1e88e5",
        "marker": "D",
    },
    "Hybrid PQ-OPAQUE\n(ML-KEM-768)": {
        "classical": 192,
        "quantum": 192,
        "overhead": 3424,
        "color": "#43a047",
        "marker": "s",
    },
    "Hybrid PQ-OPAQUE\n(ML-KEM-1024)": {
        "classical": 256,
        "quantum": 256,
        "overhead": 4768,
        "color": "#8e24aa",
        "marker": "^",
    },
    "TLS 1.3 Hybrid\n(X25519 + ML-KEM-768)": {
        "classical": 192,
        "quantum": 192,
        "overhead": 2900,
        "color": "#ff8f00",
        "marker": "P",
    },
    "Signal PQXDH\n(X25519 + ML-KEM-768)": {
        "classical": 192,
        "quantum": 192,
        "overhead": 3168,
        "color": "#00897b",
        "marker": "*",
    },
}

# ---------------------------------------------------------------------------
# Extract arrays
# ---------------------------------------------------------------------------
names = list(protocols.keys())
classical = np.array([protocols[n]["classical"] for n in names], dtype=float)
quantum = np.array([protocols[n]["quantum"] for n in names], dtype=float)
overhead = np.array([protocols[n]["overhead"] for n in names], dtype=float)
colors = [protocols[n]["color"] for n in names]
markers = [protocols[n]["marker"] for n in names]

# ---------------------------------------------------------------------------
# Build an interpolated surface (for visual context)
# We add synthetic anchor points at the corners so griddata has coverage.
# ---------------------------------------------------------------------------
anchor_c = [64, 64, 256, 256, 128, 192]
anchor_q = [0, 256, 0, 256, 64, 128]
anchor_o = [400, 5500, 1200, 6400, 800, 2600]

all_c = np.concatenate([classical, anchor_c])
all_q = np.concatenate([quantum, anchor_q])
all_o = np.concatenate([overhead, anchor_o])

grid_c, grid_q = np.meshgrid(
    np.linspace(64, 256, 60),
    np.linspace(0, 256, 60),
)
grid_o = griddata(
    np.column_stack([all_c, all_q]),
    all_o,
    (grid_c, grid_q),
    method="cubic",
)
# Clamp to positive
grid_o = np.clip(grid_o, 0, None)

# ---------------------------------------------------------------------------
# Figure
# ---------------------------------------------------------------------------
fig = plt.figure(figsize=(15, 11), facecolor="white")
ax = fig.add_subplot(111, projection="3d")

# -- Surface --
surf = ax.plot_surface(
    grid_c, grid_q, grid_o,
    cmap="viridis", alpha=0.28, edgecolor="none",
    antialiased=True, zorder=0,
)

# -- Scatter protocol points --
for i, name in enumerate(names):
    ax.scatter(
        classical[i], quantum[i], overhead[i],
        c=colors[i], marker=markers[i], s=220,
        edgecolors="black", linewidths=0.6, depthshade=False,
        zorder=5, label=name,
    )
    # Vertical drop line to z=0
    ax.plot(
        [classical[i], classical[i]],
        [quantum[i], quantum[i]],
        [0, overhead[i]],
        color=colors[i], linestyle=":", linewidth=1.0, alpha=0.6, zorder=2,
    )

# -- "Quantum-safe threshold" plane at quantum = 128 --
plane_c = np.linspace(64, 256, 2)
plane_o = np.linspace(0, 5500, 2)
plane_cc, plane_oo = np.meshgrid(plane_c, plane_o)
plane_qq = np.full_like(plane_cc, 128)
ax.plot_surface(
    plane_cc, plane_qq, plane_oo,
    color="#ffcdd2", alpha=0.15, edgecolor="#e57373", linewidth=0.5,
    zorder=1,
)
ax.text(
    250, 128, 5200,
    "Квантово-безпечний поріг\n(≥128 квантових біт)",
    color="#c62828", fontsize=8.5, fontstyle="italic",
    ha="right",
)

# ---------------------------------------------------------------------------
# Labels and title
# ---------------------------------------------------------------------------
ax.set_xlabel("Класична безпека (біти)", fontsize=11, labelpad=14)
ax.set_ylabel("Квантова безпека (біти)", fontsize=11, labelpad=14)
ax.set_zlabel("Накладні витрати обміну ключами (байти)", fontsize=11, labelpad=12)
ax.set_title(
    "Порівняння протоколів: безпека vs. накладні витрати",
    fontsize=16, fontweight="bold", pad=22,
)

ax.set_xlim(64, 270)
ax.set_ylim(-10, 270)
ax.set_zlim(0, 5500)
ax.view_init(elev=20, azim=-58)

# Legend
ax.legend(
    loc="upper left", fontsize=8, framealpha=0.9,
    edgecolor="#bdbdbd", borderpad=1.0, labelspacing=1.0,
    handletextpad=0.6, ncol=1,
)

# Color-bar for the surface
cbar = fig.colorbar(surf, ax=ax, shrink=0.45, aspect=18, pad=0.09)
cbar.set_label("Оцінка накладних витрат (байти)", fontsize=9)

plt.tight_layout()

# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------
png_path = os.path.join(OUTPUT_DIR, "security_surface_3d.png")
svg_path = os.path.join(OUTPUT_DIR, "security_surface_3d.svg")
fig.savefig(png_path, dpi=300, bbox_inches="tight", facecolor="white")
fig.savefig(svg_path, format="svg", bbox_inches="tight", facecolor="white")
plt.close(fig)

print(f"Saved: {png_path}")
print(f"Saved: {svg_path}")
