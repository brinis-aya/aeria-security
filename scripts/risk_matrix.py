"""Draw the EBIOS RM risk map, before and after treatment (docs/figures/matrice-risques.svg)."""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, Rectangle  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "docs" / "figures" / "matrice-risques.svg"
INK, INK2, SURFACE = "#1f2328", "#57606a", "#ffffff"
# acceptability zones: green = acceptable, amber = tolerable under surveillance, red = unacceptable
ZONE = {"ok": "#d9f0de", "warn": "#fdf0c4", "bad": "#f9d3cf"}

# (name, gravity, likelihood before, likelihood after)
RISKS = [("R1", 4, 3, 2), ("R2", 3, 4, 1), ("R3", 3, 3, 1), ("R4", 3, 2, 1), ("R5", 2, 3, 2)]
LABELS = {"R1": "R1 épisode masqué", "R2": "R2 injection MQTT", "R3": "R3 rançongiciel",
          "R4": "R4 chaîne logicielle", "R5": "R5 vandalisme"}


def zone(g: int, v: int) -> str:
    s = g + v
    return "bad" if s >= 6 else ("warn" if s == 5 else "ok")


def main() -> None:
    fig, ax = plt.subplots(figsize=(7.6, 6.2))
    fig.patch.set_facecolor(SURFACE)
    for v in range(1, 5):
        for g in range(1, 5):
            ax.add_patch(Rectangle((v - 0.5, g - 0.5), 1, 1, facecolor=ZONE[zone(g, v)], edgecolor=SURFACE, lw=3))
    offsets = {"R2": (0.0, 0.18), "R3": (0.0, -0.18), "R4": (0.0, 0.0), "R1": (0, 0), "R5": (0, 0)}
    after_off = {"R2": (-0.22, 0.2), "R3": (0.0, 0.0), "R4": (0.22, -0.2), "R1": (0, 0), "R5": (0, 0)}
    for name, g, vb, va in RISKS:
        bx, by = vb + offsets[name][0], g + offsets[name][1]
        axx, ayy = va + after_off[name][0], g + after_off[name][1]
        ax.add_patch(FancyArrowPatch((bx, by), (axx, ayy), arrowstyle="-|>", mutation_scale=14,
                                     color=INK2, lw=1.4, shrinkA=13, shrinkB=13))
        ax.scatter([bx], [by], s=420, facecolor=SURFACE, edgecolor=INK, lw=1.8, zorder=3)
        ax.text(bx, by, name, ha="center", va="center", fontsize=9, fontweight="bold", color=INK, zorder=4)
        ax.scatter([axx], [ayy], s=420, facecolor=INK, edgecolor=INK, zorder=3)
        ax.text(axx, ayy, name, ha="center", va="center", fontsize=9, fontweight="bold", color=SURFACE, zorder=4)
    ax.set_xlim(0.5, 4.5)
    ax.set_ylim(0.5, 4.5)
    ax.set_xticks(range(1, 5), ["V1\npeu vraisemblable", "V2\nvraisemblable", "V3\ntrès vraisemblable", "V4\nquasi certain"],
                  fontsize=8.5, color=INK2)
    ax.set_yticks(range(1, 5), ["G1 mineure", "G2 significative", "G3 grave", "G4 critique"], fontsize=8.5, color=INK2)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    ax.set_title("Risques Aeria : avant (cercle blanc) et après traitement (disque plein)",
                 loc="left", fontsize=11, fontweight="bold", color=INK)
    legend = "   ".join(LABELS[r[0]] for r in RISKS)
    fig.text(0.02, 0.015, legend, fontsize=8, color=INK2)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, format="svg")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
