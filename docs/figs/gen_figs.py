#!/usr/bin/env python3
"""Generate head-to-head figures for docs/techreport-circom-prover.md.

Stdlib only. Rerun: python3 docs/figs/gen_figs.py
Inputs are the measured numbers recorded in the report (see SOURCES).
"""
import math
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)))
INK = "#1a1a1a"
GRID = "#d8d8d8"
C_CIRCOM = "#2f6fed"
C_ARK = "#e07a00"
FONT = "font-family='Helvetica,Arial,sans-serif'"


def svg_open(w, h, title):
    return [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{w}' height='{h}' viewBox='0 0 {w} {h}'>",
        f"<title>{title}</title>",
        f"<text x='{w/2:.0f}' y='26' text-anchor='middle' font-size='17' font-weight='bold' fill='{INK}' {FONT}>{title}</text>",
    ]


def hbar(parts, y, x, w, h, color, label, label_side="right"):
    parts.append(f"<rect x='{x:.1f}' y='{y:.1f}' width='{w:.1f}' height='{h}' fill='{color}'/>")
    lx = x + w + 8
    anchor = "start"
    if label_side == "inside":
        lx = x + w - 8
        anchor = "end"
    parts.append(
        f"<text x='{lx:.1f}' y='{y + h/2 + 5:.1f}' text-anchor='{anchor}' "
        f"font-size='13' fill='{INK}' {FONT}>{label}</text>"
    )


def footnote(parts, w, y, lines):
    for i, ln in enumerate(lines):
        parts.append(
            f"<text x='16' y='{y + i*17}' font-size='11.5' fill='#555' {FONT}>{ln}</text>"
        )


def fig_prove():
    w, h = 640, 250
    p = svg_open(w, h, "Groth16 prove time, same session (i9-13900K)")
    left, right = 150, 470
    vmax = 2.6
    rows = [("snarkjs (circom)", 2.45, C_CIRCOM), ("arkworks (mirror)", 1.21, C_ARK)]
    for i, (name, v, c) in enumerate(rows):
        y = 70 + i * 52
        p.append(f"<text x='{left-10}' y='{y+20}' text-anchor='end' font-size='13' fill='{INK}' {FONT}>{name}</text>")
        bw = (right - left) * v / vmax
        hbar(p, y, left, bw, 28, c, f"{v:.2f} s")
    for t in (0, 1, 2):
        x = left + (right - left) * t / vmax
        p.append(f"<line x1='{x:.1f}' y1='62' x2='{x:.1f}' y2='180' stroke='{GRID}'/>")
        p.append(f"<text x='{x:.1f}' y='196' text-anchor='middle' font-size='12' fill='#555' {FONT}>{t} s</text>")
    footnote(p, w, 222, ["snarkjs: single wall sample (6.56 s user) incl. runtime startup.",
                         "arkworks: criterion median, n=10, release."])
    p.append("</svg>")
    open(os.path.join(OUT, "prove_time.svg"), "w").write("\n".join(p))


def fig_constraints():
    w, h = 640, 250
    p = svg_open(w, h, "Constraint counts, same relation")
    left, right = 210, 480
    vmax = 135_000
    rows = [
        ("circom (non-linear)", 127_248, C_CIRCOM),
        ("arkworks (total)", 129_222, C_ARK),
    ]
    for i, (name, v, c) in enumerate(rows):
        y = 70 + i * 52
        p.append(f"<text x='{left-10}' y='{y+20}' text-anchor='end' font-size='13' fill='{INK}' {FONT}>{name}</text>")
        bw = (right - left) * v / vmax
        hbar(p, y, left, bw, 28, c, f"{v:,}")
    for t in (0, 50_000, 100_000):
        x = left + (right - left) * t / vmax
        p.append(f"<line x1='{x:.1f}' y1='62' x2='{x:.1f}' y2='180' stroke='{GRID}'/>")
        p.append(f"<text x='{x:.1f}' y='196' text-anchor='middle' font-size='12' fill='#555' {FONT}>{t//1000}k</text>")
    footnote(p, w, 222, ["arkworks: 9 instance + 127,248 witness vars. circom substitutes linear constraints out",
                         "(reported linear: 0; 125,283 wires). S-box multiplies dominate both."])
    p.append("</svg>")
    open(os.path.join(OUT, "constraints.svg"), "w").write("\n".join(p))


def fig_benches():
    groups = [
        ("des / single_block", 1.25e-6, 1.19e-6),
        ("des / session_precheck", 20e-6, 19.8e-6),
        ("r1cs / synthesize_blank", 92e-3, 87.7e-3),
        ("groth16 / prove", 1.2, 1.21),
        ("groth16 / verify", 2.1e-3, 2.07e-3),
    ]
    w = 640
    top, gh, gap = 64, 30, 26
    h = top + len(groups) * (2 * 20 + gap) + 76
    p = svg_open(w, h, "Session bench suite, prover reference vs circom mirror (log scale)")
    left, right = 230, 560
    vmin, vmax = 0.8e-6, 3.0

    def x(v):
        return left + (math.log10(v) - math.log10(vmin)) / (math.log10(vmax) - math.log10(vmin)) * (right - left)

    ticks = [(1e-6, "1µs"), (1e-5, "10µs"), (1e-4, "100µs"), (1e-3, "1ms"),
             (1e-2, "10ms"), (1e-1, "100ms"), (1, "1s")]
    for v, lab in ticks:
        p.append(f"<line x1='{x(v):.1f}' y1='{top-8}' x2='{x(v):.1f}' y2='{top + len(groups)*(40+gap)}' stroke='{GRID}'/>")
        p.append(f"<text x='{x(v):.1f}' y='{top + len(groups)*(40+gap) + 18}' text-anchor='middle' font-size='11' fill='#555' {FONT}>{lab}</text>")
    for i, (name, vref, vmeas) in enumerate(groups):
        gy = top + i * (40 + gap)
        p.append(f"<text x='{left-10}' y='{gy+26}' text-anchor='end' font-size='12.5' fill='{INK}' {FONT}>{name}</text>")
        hbar(p, gy, x(vmin), x(vref) - x(vmin), 16, "#9db9f5", "")
        hbar(p, gy + 20, x(vmin), x(vmeas) - x(vmin), 16, C_ARK, "")
    # legend
    ly = h - 40
    p.append(f"<rect x='{left}' y='{ly-12}' width='14' height='14' fill='#9db9f5'/>")
    p.append(f"<text x='{left+20}' y='{ly}' font-size='12' fill='{INK}' {FONT}>prover reference</text>")
    p.append(f"<rect x='{left+170}' y='{ly-12}' width='14' height='14' fill='{C_ARK}'/>")
    p.append(f"<text x='{left+190}' y='{ly}' font-size='12' fill='{INK}' {FONT}>circom mirror measured</text>")
    footnote(p, w, h - 16, ["prover values: reference table in prover/benches/session.rs. mirror: criterion medians, this box."])
    p.append("</svg>")
    open(os.path.join(OUT, "benches.svg"), "w").write("\n".join(p))


fig_prove()
fig_constraints()
fig_benches()
print("wrote prove_time.svg constraints.svg benches.svg")
