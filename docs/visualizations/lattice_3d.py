#!/usr/bin/env python3
"""
3D Visualization of Module-LWE Lattice Structure for ML-KEM-768.

Renders the lattice grid with basis vectors, Gaussian error distribution
around lattice points, and illustrates the closest vector problem (CVP)
that underpins the hardness assumption of ML-KEM.

Output: lattice_3d.png (300 dpi), lattice_3d.svg
"""

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D  # noqa: F401
from matplotlib.patches import FancyArrowPatch
from mpl_toolkits.mplot3d import proj3d
import os

# ---------------------------------------------------------------------------
# Helper: 3-D arrow that works correctly with mplot3d projection
# ---------------------------------------------------------------------------
class Arrow3D(FancyArrowPatch):
    """Draw a 3-D arrow on an mpl_toolkits.mplot3d axis."""

    def __init__(self, xs, ys, zs, *args, **kwargs):
        super().__init__((0, 0), (0, 0), *args, **kwargs)
        self._verts3d = xs, ys, zs

    def do_3d_projection(self, renderer=None):
        xs, ys, zs = self._verts3d
        xs_2d, ys_2d, zs_2d = proj3d.proj_transform(xs, ys, zs, self.axes.M)
        self.set_positions((xs_2d[0], ys_2d[0]), (xs_2d[1], ys_2d[1]))
        return min(zs_2d)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
SEED = 42
np.random.seed(SEED)

# Lattice parameters (simplified 3-D analog of Module-LWE)
LATTICE_RANGE = 3          # lattice indices from -RANGE to +RANGE
SIGMA_ERROR = 0.22         # standard deviation of centred binomial / Gaussian noise
N_ERROR_SAMPLES = 120      # points per lattice node for the error cloud
CVP_TARGET_OFFSET = np.array([0.38, 0.45, 0.30])  # offset of the "target" from a lattice point

# Basis vectors (slightly skewed to look more interesting than the identity)
B1 = np.array([1.0, 0.15, 0.05])
B2 = np.array([0.10, 1.0, 0.12])
B3 = np.array([0.08, 0.05, 1.0])
BASIS = np.column_stack([B1, B2, B3])  # 3x3

# ---------------------------------------------------------------------------
# Generate lattice points
# ---------------------------------------------------------------------------
indices = np.arange(-LATTICE_RANGE, LATTICE_RANGE + 1)
grid = np.array(np.meshgrid(indices, indices, indices)).reshape(3, -1).T  # Nx3 integer coords
lattice_pts = grid @ BASIS.T  # Nx3 real coords

# ---------------------------------------------------------------------------
# Generate Gaussian error clouds around a subset of points (inner cube only)
# ---------------------------------------------------------------------------
inner_mask = np.all(np.abs(grid) <= 1, axis=1)
inner_pts = lattice_pts[inner_mask]

cloud_pts = []
for pt in inner_pts:
    noise = np.random.normal(0, SIGMA_ERROR, size=(N_ERROR_SAMPLES, 3))
    cloud_pts.append(pt + noise)
cloud_pts = np.vstack(cloud_pts)

# ---------------------------------------------------------------------------
# CVP illustration: pick a lattice point and offset target
# ---------------------------------------------------------------------------
cvp_lattice_point = lattice_pts[np.argmin(np.linalg.norm(lattice_pts, axis=1))]  # origin
cvp_target = cvp_lattice_point + CVP_TARGET_OFFSET

# ---------------------------------------------------------------------------
# Figure
# ---------------------------------------------------------------------------
fig = plt.figure(figsize=(14, 11), facecolor="white")
ax = fig.add_subplot(111, projection="3d", computed_zorder=False)

# -- 1. Lattice points (outer = small grey, inner = blue) --
outer_mask = ~inner_mask
ax.scatter(
    lattice_pts[outer_mask, 0],
    lattice_pts[outer_mask, 1],
    lattice_pts[outer_mask, 2],
    c="#9e9e9e", s=18, alpha=0.35, depthshade=True, zorder=1,
    label="Точки решітки (зовнішні)",
)
ax.scatter(
    inner_pts[:, 0], inner_pts[:, 1], inner_pts[:, 2],
    c="#1565c0", s=50, alpha=0.9, edgecolors="#0d47a1", linewidths=0.5,
    depthshade=True, zorder=3,
    label="Точки решітки (внутрішні)",
)

# -- 2. Gaussian error cloud --
ax.scatter(
    cloud_pts[:, 0], cloud_pts[:, 1], cloud_pts[:, 2],
    c=cloud_pts[:, 2], cmap="plasma", s=3, alpha=0.18, depthshade=True, zorder=2,
    label=f"Гауссова помилка (σ={SIGMA_ERROR})",
)

# -- 3. Basis vectors from origin --
colors_basis = ["#d32f2f", "#388e3c", "#f57c00"]
labels_basis = ["b₁", "b₂", "b₃"]
vectors = [B1, B2, B3]
for vec, col, lab in zip(vectors, colors_basis, labels_basis):
    arrow = Arrow3D(
        [0, vec[0]], [0, vec[1]], [0, vec[2]],
        mutation_scale=16, lw=2.5, arrowstyle="-|>", color=col,
    )
    ax.add_artist(arrow)
    ax.text(
        vec[0] * 1.12, vec[1] * 1.12, vec[2] * 1.12,
        lab, color=col, fontsize=14, fontweight="bold", ha="center",
    )

# -- 4. CVP target and dashed line to closest lattice point --
ax.scatter(
    [cvp_target[0]], [cvp_target[1]], [cvp_target[2]],
    c="#e91e63", marker="*", s=260, edgecolors="#880e4f", linewidths=0.7,
    zorder=5, label="Цільова точка (CVP)",
)
ax.plot(
    [cvp_lattice_point[0], cvp_target[0]],
    [cvp_lattice_point[1], cvp_target[1]],
    [cvp_lattice_point[2], cvp_target[2]],
    linestyle="--", color="#e91e63", linewidth=1.8, zorder=4,
)
mid = (cvp_lattice_point + cvp_target) / 2
ax.text(
    mid[0] + 0.08, mid[1] + 0.08, mid[2] + 0.15,
    "CVP відстань", color="#880e4f", fontsize=10, fontstyle="italic",
)

# -- 5. Light wireframe edges for inner cube --
for i in range(len(inner_pts)):
    for j in range(i + 1, len(inner_pts)):
        diff = np.abs(grid[inner_mask][i] - grid[inner_mask][j])
        if np.sum(diff) == 1:  # Manhattan distance 1 = edge
            ax.plot(
                [inner_pts[i, 0], inner_pts[j, 0]],
                [inner_pts[i, 1], inner_pts[j, 1]],
                [inner_pts[i, 2], inner_pts[j, 2]],
                color="#90caf9", linewidth=0.4, alpha=0.45, zorder=0,
            )

# ---------------------------------------------------------------------------
# Labels, title, legend
# ---------------------------------------------------------------------------
ax.set_xlabel("x₁", fontsize=12, labelpad=10)
ax.set_ylabel("x₂", fontsize=12, labelpad=10)
ax.set_zlabel("x₃", fontsize=12, labelpad=10)
ax.set_title(
    "Структура решітки Module-LWE для ML-KEM-768",
    fontsize=16, fontweight="bold", pad=20,
)

ax.legend(
    loc="upper left", fontsize=9, framealpha=0.85, edgecolor="#bdbdbd",
    borderpad=1.0, labelspacing=0.8,
)

# Viewing angle
ax.view_init(elev=22, azim=-52)
ax.set_box_aspect([1, 1, 1])

# Annotation box
textstr = (
    "Module-LWE (k=3, n=256, q=3329)\n"
    "Безпека базується на складності\n"
    "знаходження найближчого вектора\n"
    "решітки (CVP/SVP) у присутності\n"
    "гауссового шуму."
)
props = dict(boxstyle="round,pad=0.6", facecolor="#e3f2fd", alpha=0.88, edgecolor="#90caf9")
ax.text2D(
    0.02, 0.22, textstr, transform=ax.transAxes,
    fontsize=9, verticalalignment="top", bbox=props,
)

plt.tight_layout()

# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------
png_path = os.path.join(OUTPUT_DIR, "lattice_3d.png")
svg_path = os.path.join(OUTPUT_DIR, "lattice_3d.svg")
fig.savefig(png_path, dpi=300, bbox_inches="tight", facecolor="white")
fig.savefig(svg_path, format="svg", bbox_inches="tight", facecolor="white")
plt.close(fig)

print(f"Saved: {png_path}")
print(f"Saved: {svg_path}")
