#!/usr/bin/env python3
"""
3D Threat Landscape: Classic OPAQUE vs. Hybrid PQ-OPAQUE Over Time.

Two surfaces show how achieved security level changes as quantum computing
power grows over the next 30 years.  Classic OPAQUE's effective security
declines once a CRQC (Cryptographically Relevant Quantum Computer) appears,
while Hybrid PQ-OPAQUE maintains its security level.

Output: threat_landscape_3d.png (300 dpi), threat_landscape_3d.svg
"""

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D  # noqa: F401
from matplotlib import cm
from matplotlib.colors import Normalize
import os

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------
T_MAX = 30                   # years
QUBITS_LOG_MIN = 1           # log10 of logical qubits
QUBITS_LOG_MAX = 5           # log10 (100 000 logical qubits)
CRQC_QUBITS_LOG = 3.6        # ~4000 logical qubits — CRQC threshold (approx.)
CRQC_YEAR_ESTIMATE = 15       # years from now — central estimate for CRQC

RESOLUTION = 80

# Grids
time_lin = np.linspace(0, T_MAX, RESOLUTION)
qubits_log_lin = np.linspace(QUBITS_LOG_MIN, QUBITS_LOG_MAX, RESOLUTION)
T, Q = np.meshgrid(time_lin, qubits_log_lin)

# ---------------------------------------------------------------------------
# Security models
# ---------------------------------------------------------------------------
# Classic OPAQUE: 128-bit classical.  Grover halves symmetric key strength,
# but the real threat is Shor on ECDH.  Once qubits exceed CRQC threshold
# AND sufficient time has passed for engineering maturity, security collapses.
#
# We model a smooth sigmoid collapse:
#   sec_classic(t, q) = 128 * sigmoid(- (q - crqc_q) * alpha - (t - crqc_t) * beta)
#
# Hybrid PQ-OPAQUE: ML-KEM-768 provides 192-bit post-quantum security.
# Even if DH is broken, the KEM component keeps security at >= 192 bits
# against quantum, and Grover only reduces symmetric from 256 -> 128.
# Net: security stays roughly constant, minor theoretical Grover dip.

ALPHA_Q = 3.5   # steepness w.r.t. qubit axis
BETA_T = 0.20   # steepness w.r.t. time axis

def sigmoid(x):
    return 1.0 / (1.0 + np.exp(-x))

# Classic OPAQUE security surface
collapse_arg = ALPHA_Q * (Q - CRQC_QUBITS_LOG) + BETA_T * (T - CRQC_YEAR_ESTIMATE)
sec_classic = 128 * sigmoid(-collapse_arg)
sec_classic = np.clip(sec_classic, 0, 128)

# Hybrid PQ-OPAQUE security surface
# Slight Grover dip at extremely high qubit counts (cosmetic, not dramatic)
grover_reduction = 8 * sigmoid(2.0 * (Q - 4.0))  # at most ~8 bits reduction
sec_hybrid = 192 - grover_reduction
sec_hybrid = np.clip(sec_hybrid, 128, 192)

# ---------------------------------------------------------------------------
# Figure
# ---------------------------------------------------------------------------
fig = plt.figure(figsize=(16, 11), facecolor="white")
ax = fig.add_subplot(111, projection="3d")

# -- Classic OPAQUE surface (red tones) --
norm_classic = Normalize(vmin=0, vmax=128)
surf_c = ax.plot_surface(
    T, Q, sec_classic,
    cmap="Reds_r", alpha=0.65, edgecolor="none",
    antialiased=True, zorder=2,
)

# -- Hybrid PQ-OPAQUE surface (green/blue tones) --
norm_hybrid = Normalize(vmin=128, vmax=192)
surf_h = ax.plot_surface(
    T, Q, sec_hybrid,
    cmap="winter", alpha=0.65, edgecolor="none",
    antialiased=True, zorder=3,
)

# -- CRQC threshold plane --
crqc_time = np.linspace(0, T_MAX, 2)
crqc_sec = np.linspace(0, 200, 2)
CT, CS = np.meshgrid(crqc_time, crqc_sec)
CQ = np.full_like(CT, CRQC_QUBITS_LOG)
ax.plot_surface(
    CT, CQ, CS,
    color="#ffeb3b", alpha=0.15, edgecolor="#fbc02d", linewidth=0.6,
    zorder=1,
)
ax.text(
    T_MAX * 0.92, CRQC_QUBITS_LOG + 0.15, 170,
    f"CRQC поріг\n(~{10**CRQC_QUBITS_LOG:.0f} логічних кубітів)",
    color="#f57f17", fontsize=9, fontweight="bold",
    ha="right", va="center",
    bbox=dict(boxstyle="round,pad=0.3", facecolor="#fff9c4", alpha=0.9, edgecolor="#fbc02d"),
)

# -- "Harvest now, decrypt later" annotation --
ax.text(
    2, QUBITS_LOG_MIN + 0.3, 55,
    '"Збери зараз —\n  розшифруй пізніше"',
    color="#b71c1c", fontsize=8.5, fontstyle="italic",
    bbox=dict(boxstyle="round,pad=0.3", facecolor="#ffcdd2", alpha=0.85, edgecolor="#e57373"),
)

# -- Year marker for CRQC estimate --
ax.plot(
    [CRQC_YEAR_ESTIMATE, CRQC_YEAR_ESTIMATE],
    [QUBITS_LOG_MIN, QUBITS_LOG_MAX],
    [0, 0],
    color="#ff6f00", linestyle="--", linewidth=1.5, alpha=0.7, zorder=4,
)
ax.text(
    CRQC_YEAR_ESTIMATE, QUBITS_LOG_MIN - 0.2, -5,
    f"~{CRQC_YEAR_ESTIMATE} років",
    color="#e65100", fontsize=9, ha="center", fontweight="bold",
)

# -- Contour lines on the classic surface for clarity --
ax.contour(
    T, Q, sec_classic,
    levels=[16, 32, 64, 96, 112, 128],
    cmap="Reds_r", linewidths=0.6, linestyles=":", alpha=0.5,
    zdir="z", offset=0,
)

# ---------------------------------------------------------------------------
# Labels and title
# ---------------------------------------------------------------------------
ax.set_xlabel("Час (роки від сьогодні)", fontsize=11, labelpad=14)
ax.set_ylabel("Квантова потужність\n(log₁₀ логічних кубітів)", fontsize=11, labelpad=14)
ax.set_zlabel("Досягнутий рівень безпеки (біти)", fontsize=11, labelpad=12)

ax.set_xlim(0, T_MAX)
ax.set_ylim(QUBITS_LOG_MIN, QUBITS_LOG_MAX)
ax.set_zlim(0, 210)

# Custom y-tick labels to show actual qubit counts
yticks = [1, 2, 3, 4, 5]
ax.set_yticks(yticks)
ax.set_yticklabels([f"10{chr(0x2070+d)}" if d < 4 else f"10{chr(0x2074+d-4)}"
                     for d in yticks])
# Fix superscript: use plain text
ax.set_yticklabels(["10", "100", "1K", "10K", "100K"], fontsize=8)

ax.set_title(
    "Еволюція загроз: класичний vs. гібридний OPAQUE",
    fontsize=16, fontweight="bold", pad=22,
)

ax.view_init(elev=22, azim=-52)

# ---------------------------------------------------------------------------
# Legend (manual proxy artists)
# ---------------------------------------------------------------------------
from matplotlib.patches import Patch
legend_elements = [
    Patch(facecolor="#ef5350", alpha=0.7, edgecolor="#b71c1c",
          label="Classic OPAQUE (X25519, 128-біт класична)"),
    Patch(facecolor="#4fc3f7", alpha=0.7, edgecolor="#01579b",
          label="Hybrid PQ-OPAQUE (ML-KEM-768, 192-біт PQ)"),
    Patch(facecolor="#ffeb3b", alpha=0.3, edgecolor="#fbc02d",
          label="CRQC поріг (криптографічно значущий КК)"),
]
ax.legend(
    handles=legend_elements, loc="upper right",
    fontsize=9, framealpha=0.92, edgecolor="#bdbdbd",
    borderpad=1.0, labelspacing=0.9,
)

# Summary box
summary = (
    "Модель загроз:\n"
    "  \u2022 Classic OPAQUE: безпека падає після CRQC\n"
    "    (алгоритм Шора ламає ECDH)\n"
    "  \u2022 Hybrid PQ-OPAQUE: ML-KEM-768 зберігає\n"
    "    ≥128-біт безпеки навіть проти CRQC\n"
    "  \u2022 Грувер знижує симетричну безпеку\n"
    "    лише на ~√N (незначний ефект)"
)
props = dict(boxstyle="round,pad=0.5", facecolor="#e8eaf6", alpha=0.92, edgecolor="#7986cb")
ax.text2D(
    0.01, 0.30, summary, transform=ax.transAxes,
    fontsize=8.5, verticalalignment="top", bbox=props,
)

plt.tight_layout()

# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------
png_path = os.path.join(OUTPUT_DIR, "threat_landscape_3d.png")
svg_path = os.path.join(OUTPUT_DIR, "threat_landscape_3d.svg")
fig.savefig(png_path, dpi=300, bbox_inches="tight", facecolor="white")
fig.savefig(svg_path, format="svg", bbox_inches="tight", facecolor="white")
plt.close(fig)

print(f"Saved: {png_path}")
print(f"Saved: {svg_path}")
