#!/usr/bin/env python3
"""
3D Visualization of the Hybrid Key Derivation Process in Hybrid PQ-OPAQUE.

Shows three DH shared secrets and one KEM shared secret flowing into
combined_ikm, then HKDF-Extract producing PRK, and HKDF-Expand branching
into four session keys.  Rendered as a 3-D flowchart with matplotlib.

Output: key_derivation_3d.png (300 dpi), key_derivation_3d.svg
"""

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D, art3d  # noqa: F401
from mpl_toolkits.mplot3d import proj3d
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
import os

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Arrow helper
# ---------------------------------------------------------------------------
class Arrow3D(FancyArrowPatch):
    def __init__(self, xs, ys, zs, *args, **kwargs):
        super().__init__((0, 0), (0, 0), *args, **kwargs)
        self._verts3d = xs, ys, zs

    def do_3d_projection(self, renderer=None):
        xs, ys, zs = self._verts3d
        xs2, ys2, zs2 = proj3d.proj_transform(xs, ys, zs, self.axes.M)
        self.set_positions((xs2[0], ys2[0]), (xs2[1], ys2[1]))
        return min(zs2)


def draw_arrow(ax, start, end, color="#37474f", lw=2.0, style="-|>"):
    a = Arrow3D(
        [start[0], end[0]], [start[1], end[1]], [start[2], end[2]],
        mutation_scale=14, lw=lw, arrowstyle=style, color=color,
    )
    ax.add_artist(a)


def draw_pipe(ax, start, end, color="#90a4ae", lw=5, alpha=0.35):
    """Draw a thick translucent tube between two 3-D points."""
    ax.plot(
        [start[0], end[0]], [start[1], end[1]], [start[2], end[2]],
        color=color, linewidth=lw, alpha=alpha, solid_capstyle="round",
    )


# ---------------------------------------------------------------------------
# Node positions  (x = stage,  y = horizontal spread,  z = depth/layer)
# ---------------------------------------------------------------------------
# Stage 0 – Input secrets
dh1  = np.array([0.0,  3.0,  2.0])
dh2  = np.array([0.0,  1.0,  2.0])
dh3  = np.array([0.0, -1.0,  2.0])
kem  = np.array([0.0, -3.0,  2.0])

# Stage 1 – combined_ikm
cikm = np.array([3.5,  0.0,  2.0])

# Stage 2 – HKDF-Extract → PRK
prk  = np.array([6.5,  0.0,  2.0])

# Stage 3 – HKDF-Expand outputs
key_session  = np.array([10.0,  3.0,  3.0])
key_master   = np.array([10.0,  1.0,  1.5])
key_resp_mac = np.array([10.0, -1.0,  3.0])
key_init_mac = np.array([10.0, -3.0,  1.5])

# ---------------------------------------------------------------------------
# Figure
# ---------------------------------------------------------------------------
fig = plt.figure(figsize=(16, 10), facecolor="white")
ax = fig.add_subplot(111, projection="3d", computed_zorder=False)

# ---- Pipes (flow lines) ----
pipe_color_dh  = "#42a5f5"
pipe_color_kem = "#ab47bc"
pipe_color_hkdf = "#66bb6a"
pipe_color_out  = "#ffa726"

for src in [dh1, dh2, dh3]:
    draw_pipe(ax, src, cikm, color=pipe_color_dh, lw=6, alpha=0.30)
    draw_arrow(ax, src, cikm, color="#1565c0", lw=1.8)

draw_pipe(ax, kem, cikm, color=pipe_color_kem, lw=6, alpha=0.30)
draw_arrow(ax, kem, cikm, color="#7b1fa2", lw=1.8)

draw_pipe(ax, cikm, prk, color=pipe_color_hkdf, lw=7, alpha=0.30)
draw_arrow(ax, cikm, prk, color="#2e7d32", lw=2.2)

for dst in [key_session, key_master, key_resp_mac, key_init_mac]:
    draw_pipe(ax, prk, dst, color=pipe_color_out, lw=5, alpha=0.25)
    draw_arrow(ax, prk, dst, color="#e65100", lw=1.6)

# ---- Node spheres ----
node_specs = [
    # (position, color, size, label, label_offset)
    (dh1, "#1e88e5", 180, "DH₁ (ristretto255)\nsk_c · pk_s", np.array([0, 0.5, 0.5])),
    (dh2, "#1e88e5", 180, "DH₂ (ristretto255)\nsk_c · pk_s_oprf", np.array([0, 0.5, 0.5])),
    (dh3, "#1e88e5", 180, "DH₃ (ristretto255)\nesk_c · pk_s", np.array([0, 0.5, 0.5])),
    (kem, "#8e24aa", 200, "KEM shared secret\nML-KEM-768\nDecaps(sk, ct)", np.array([0, -1.0, 0.6])),
    (cikm, "#00897b", 260, "combined_ikm\nConcat(DH₁‖DH₂‖DH₃‖KEM_ss)", np.array([0, 0.0, 1.0])),
    (prk, "#2e7d32", 280, "PRK\nHKDF-Extract(salt, combined_ikm)", np.array([0, 0.0, 1.0])),
    (key_session, "#ef6c00", 160, "session_key\n(AES-256)", np.array([0, 0.5, 0.5])),
    (key_master, "#ef6c00", 160, "handshake_secret", np.array([0, 0.5, -0.7])),
    (key_resp_mac, "#ef6c00", 160, "server_mac_key\n(HMAC)", np.array([0, 0.5, 0.5])),
    (key_init_mac, "#ef6c00", 160, "client_mac_key\n(HMAC)", np.array([0, -0.8, -0.7])),
]

for pos, col, sz, label, loff in node_specs:
    ax.scatter(
        pos[0], pos[1], pos[2],
        c=col, s=sz, edgecolors="black", linewidths=0.5,
        depthshade=False, zorder=5, alpha=0.92,
    )
    lp = pos + loff
    ax.text(
        lp[0], lp[1], lp[2], label,
        fontsize=7.8, ha="center", va="bottom",
        color="#212121", fontweight="normal",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.82, edgecolor=col, linewidth=0.8),
    )

# ---- Stage labels (at the bottom) ----
stage_labels = [
    (0.0,  0.0, -0.3, "Вхідні секрети", "#546e7a"),
    (3.5,  0.0, -0.3, "Конкатенація", "#00695c"),
    (6.5,  0.0, -0.3, "HKDF-Extract", "#1b5e20"),
    (10.0, 0.0, -0.3, "HKDF-Expand", "#e65100"),
]
for x, y, z, txt, col in stage_labels:
    ax.text(
        x, y, z, txt, fontsize=10, ha="center", va="top",
        color=col, fontweight="bold", fontstyle="italic",
    )

# ---------------------------------------------------------------------------
# Axes / view
# ---------------------------------------------------------------------------
ax.set_xlim(-1.5, 11.5)
ax.set_ylim(-5, 5)
ax.set_zlim(-1, 5)
ax.set_axis_off()

ax.view_init(elev=18, azim=-68)

ax.set_title(
    "Гібридна деривація ключів у Hybrid PQ-OPAQUE",
    fontsize=16, fontweight="bold", pad=18, color="#212121",
)

# Legend annotation box
legend_text = (
    "Потік ключового матеріалу:\n"
    "  \u2022 3 × DH (ristretto255) — класична безпека\n"
    "  \u2022 1 × KEM ss (ML-KEM-768) — квантова стійкість\n"
    "  \u2022 HKDF (SHA-512) — деривація 4 ключів"
)
props = dict(boxstyle="round,pad=0.5", facecolor="#f3e5f5", alpha=0.9, edgecolor="#ab47bc")
ax.text2D(
    0.01, 0.15, legend_text, transform=ax.transAxes,
    fontsize=9, verticalalignment="top", bbox=props,
)

plt.tight_layout()

# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------
png_path = os.path.join(OUTPUT_DIR, "key_derivation_3d.png")
svg_path = os.path.join(OUTPUT_DIR, "key_derivation_3d.svg")
fig.savefig(png_path, dpi=300, bbox_inches="tight", facecolor="white")
fig.savefig(svg_path, format="svg", bbox_inches="tight", facecolor="white")
plt.close(fig)

print(f"Saved: {png_path}")
print(f"Saved: {svg_path}")
