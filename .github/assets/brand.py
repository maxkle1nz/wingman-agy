#!/usr/bin/env python3
"""Wingman AGY brand assets, drawn to the DEViance visual system (brand/DEVIANCE-VISUAL-SYSTEM.md).

Outputs, next to this file:
  wingman-agy-banner-dark.svg / -light.svg   README header (1280x400), swapped by color scheme
  wingman-agy-social.svg                     GitHub social preview (1280x640); render to PNG with resvg
  wingman-agy-mark.svg                       square avatar / favicon (512x512)

Type is real: Archivo Narrow Bold (display), Archivo Narrow Bold Italic (the signal i) and
IBM Plex Mono (technical), shaped with HarfBuzz and converted to paths, so the SVGs need no
fonts at view time. Fonts (SIL OFL) are read from ./fonts or $BRAND_FONTS.

Rules honored: one signal-colored character; colors keep their roles (blue = source,
oxide = destination); no glow, gradient, bevel or chrome; the grid stays visible.
Gestures: Source Seam, Continuation Cut, Proof Ruler 01-05.

Requires: fonttools, uharfbuzz.  Usage: python brand.py
"""
import os
from pathlib import Path

import uharfbuzz as hb
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

HERE = Path(__file__).resolve().parent
FONTS = Path(os.environ.get("BRAND_FONTS") or HERE / "fonts")

# Palette (roles, not moods).
CARBON, OFFBLACK, GRAPHITE = "#050505", "#111111", "#242424"
BONE, CONCRETE = "#F0EDE4", "#85847F"
SIGNAL, SOURCE, ACTION = "#FF4A1F", "#2349D8", "#B83817"

THEMES = {
    "dark": dict(bg=CARBON, ink=BONE, micro=CONCRETE, grid=GRAPHITE, grid_op=0.55, grain=0.07),
    "light": dict(bg=BONE, ink=CARBON, micro="#55544F", grid=CONCRETE, grid_op=0.22, grain=0.0),
}


class Face:
    """A static font instance: HarfBuzz for shaping, fontTools for outlines."""

    def __init__(self, filename, wght=None):
        src = FONTS / filename
        tt = TTFont(str(src))
        if wght is not None and "fvar" in tt:
            tt = instantiateVariableFont(tt, {"wght": wght})
        self.tt = tt
        self.upem = tt["head"].unitsPerEm
        self.cap = getattr(tt["OS/2"], "sCapHeight", 0) or int(self.upem * 0.7)
        self.xh = getattr(tt["OS/2"], "sxHeight", 0) or int(self.upem * 0.5)
        tmp = HERE / f".{src.stem}-{wght}.ttf"
        tt.save(str(tmp))
        self.hb = hb.Font(hb.Face(hb.Blob.from_file_path(str(tmp))))
        tmp.unlink()
        self.glyphs = tt.getGlyphSet()
        self.order = tt.getGlyphOrder()

    def path(self, text, size, x, y, tracking=0.0):
        """Return (svg path d, advance width) for text with baseline at (x, y)."""
        buf = hb.Buffer()
        buf.add_str(text)
        buf.guess_segment_properties()
        hb.shape(self.hb, buf, {"kern": True, "liga": True})
        s = size / self.upem
        pen = SVGPathPen(self.glyphs)
        pen_x = 0.0
        for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
            name = self.order[info.codepoint]
            ox = x + (pen_x + pos.x_offset) * s
            oy = y - pos.y_offset * s
            self.glyphs[name].draw(TransformPen(pen, (s, 0, 0, -s, ox, oy)))
            pen_x += pos.x_advance + tracking * self.upem
        width = (pen_x - tracking * self.upem) * s
        return pen.getCommands(), width

    def cap_px(self, size):
        return self.cap * size / self.upem


def rect(x, y, w, h, fill, op=1.0):
    return f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" fill="{fill}" opacity="{op}"/>'


def path(d, fill, op=1.0):
    return f'<path d="{d}" fill="{fill}" opacity="{op}"/>'


def grain(op, w, h, cut=0):
    if not op:
        return []
    plate = f"0,0 {w},0 {w},{h-cut} {w-cut},{h} 0,{h}"
    return [
        f'<clipPath id="plate"><polygon points="{plate}"/></clipPath>',
        '<filter id="grain" x="0" y="0" width="100%" height="100%">'
        '<feTurbulence type="fractalNoise" baseFrequency="0.9" numOctaves="2" stitchTiles="stitch"/>'
        '<feColorMatrix values="0 0 0 0 1  0 0 0 0 1  0 0 0 0 1  0 0 0 1.4 -0.55"/></filter>',
        f'<rect width="{w}" height="{h}" filter="url(#grain)" clip-path="url(#plate)" opacity="{op}"/>',
    ]


def wordmark(disp, ital, mono, size, x, base, ink, micro, bg):
    """W i NGMAN .AGY : the signal i is lowercase italic, crossed by a diagonal slash cut."""
    out = []
    d, w1 = disp.path("W", size, x, base)
    out.append(path(d, ink))
    ix = x + w1 + size * 0.015
    di, wi = ital.path("i", size, ix, base)
    out.append(path(di, SIGNAL))
    cap = disp.cap_px(size)
    # The deviation inside the name: a slash cut through the i, on the phi-ish slope.
    cx, cy, L, t = ix + wi * 0.48, base - cap * 0.46, cap * 1.25, size * 0.016
    dx, dy = 0.53 * L / 2, 0.85 * L / 2
    # Clip the cut to the i itself, so the slash never marks its neighbours.
    cid = f"i{abs(hash((round(ix), round(base), size))) % 10**6}"
    out.append(f'<clipPath id="{cid}"><path d="{di}"/></clipPath>')
    out.append(f'<polygon clip-path="url(#{cid})" points="{cx-dx-t:.1f},{cy+dy:.1f} {cx+dx-t:.1f},{cy-dy:.1f} '
               f'{cx+dx+t:.1f},{cy-dy:.1f} {cx-dx+t:.1f},{cy+dy:.1f}" fill="{bg}"/>')
    nx = ix + wi + size * 0.02
    dn, wn = disp.path("NGMAN", size, nx, base)
    out.append(path(dn, ink))
    mx = nx + wn + size * 0.035
    msize = size * 0.2
    dm, wm = mono.path(".AGY", msize, mx, base)
    out.append(path(dm, micro))
    return out, (mx + wm) - x, cap


def proof_ruler(mono, x, base, ink, micro, labels, break_to):
    """Five pressure marks; the fifth (handoff) breaks the text boundary."""
    out, step = [], 112
    for i, lab in enumerate(labels):
        h = 8 + i * 6
        mx = x + i * step
        last = i == len(labels) - 1
        color = ACTION if last else ink
        if last:
            out.append(rect(mx, base - h, 3, h + (break_to - base), color))
        else:
            out.append(rect(mx, base - h, 2, h, color, 0.85))
        d, _ = mono.path(f"{i+1:02d} {lab}", 10.5, mx + 8, base, tracking=0.08)
        out.append(path(d, ACTION if last else micro))
    return out


def banner(theme, W=1280, H=400, social=False):
    th = THEMES[theme]
    disp = Face("ArchivoNarrow[wght].ttf", 700)
    ital = Face("ArchivoNarrow-Italic[wght].ttf", 700)
    mono = Face("IBMPlexMono-Medium.ttf")
    mono_b = Face("IBMPlexMono-SemiBold.ttf")
    M, cut = 64, 48
    e = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
         f'role="img" aria-label="Wingman AGY: your agent leads, Gemini flies wing">']
    # Continuation Cut: the plate loses its bottom-right 48x48 corner.
    e.append(f'<polygon points="0,0 {W},0 {W},{H-cut} {W-cut},{H} 0,{H}" fill="{th["bg"]}"/>')
    # The grid stays visible enough to prove structure.
    for gx in range(M, W - M + 1, 64):
        e.append(rect(gx, 0, 1, H - (cut if gx > W - cut else 0), th["grid"], th["grid_op"] * 0.5))
    e.append(rect(0, M - 1, W, 1, th["grid"], th["grid_op"]))
    e += grain(th["grain"], W, H, cut)
    # Header microtype.
    d, _ = mono.path("DEVIANCE INTELLIGENCE  /  AGENT TOOLS", 12, M, M - 20, tracking=0.14)
    e.append(path(d, th["micro"]))
    d, w = mono.path("PYTHON 3.9+  .  NO DEPENDENCIES", 12, 0, M - 20, tracking=0.14)
    e.append(f'<g transform="translate({W - M - w:.1f},0)">{path(d, th["micro"])}</g>')
    # One monumental statement.
    size = 250 if social else 212
    base = (H * 0.60) if social else 262
    wm, wwidth, cap = wordmark(disp, ital, mono_b, size, M - 6, base, th["ink"], th["micro"], th["bg"])
    e += wm
    # The declaration.
    d, _ = disp.path("YOUR AGENT LEADS. GEMINI FLIES WING.", 30 if social else 24, M, base + (62 if social else 50),
                     tracking=0.04)
    e.append(path(d, th["ink"]))
    # Source Seam: a 2 px blue line physically binding the source to the repository.
    sy = H - M + 18
    e.append(rect(M, sy - 30, 2, 36, SOURCE))
    d, ws = mono_b.path("SOURCE", 12, M + 12, sy, tracking=0.12)
    e.append(path(d, SOURCE))
    d, _ = mono.path("github.com/maxkle1nz/wingman-agy", 12, M + 12 + ws + 14, sy, tracking=0.02)
    e.append(path(d, th["ink"], 0.9))
    # Proof Ruler 01-05: brief, dispatch, run, verify, hand off; the fifth breaks into the cut.
    rx = W - M - 4 * 112 - 96
    e += proof_ruler(mono, rx, sy, th["ink"], th["micro"],
                     ["BRIEF", "DISPATCH", "RUN", "VERIFY", "HAND OFF"], H)
    # The real destination crosses the cut.
    d, wd = mono_b.path("agy setup --apply", 13, 0, H - 14, tracking=0.02)
    e.append(f'<g transform="translate({W - wd - 14:.1f},0)">{path(d, ACTION)}</g>')
    e.append("</svg>")
    return "\n".join(e)


def mark(W=512):
    """Square avatar: W and the signal i, slash-cut, on carbon."""
    disp = Face("ArchivoNarrow[wght].ttf", 700)
    ital = Face("ArchivoNarrow-Italic[wght].ttf", 700)
    size = 360
    d, w1 = disp.path("W", size, 0, 0)
    di, wi = ital.path("i", size, 0, 0)
    total = w1 + size * 0.015 + wi
    x = (W - total) / 2
    base = W / 2 + disp.cap_px(size) / 2
    e = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {W}" width="{W}" height="{W}" '
         f'role="img" aria-label="Wingman AGY">', rect(0, 0, W, W, CARBON)]
    wm, _, _ = wordmark(disp, ital, Face("IBMPlexMono-SemiBold.ttf"), size, x, base, BONE, CARBON, CARBON)
    e += wm[:4]  # W, i, clip, slash; the mark carries no NGMAN and no microtype
    e.append("</svg>")
    return "\n".join(e)


if __name__ == "__main__":
    for theme in ("dark", "light"):
        (HERE / f"wingman-agy-banner-{theme}.svg").write_text(banner(theme))
    (HERE / "wingman-agy-social.svg").write_text(banner("dark", 1280, 640, social=True))
    (HERE / "wingman-agy-mark.svg").write_text(mark())
    print("wrote banner-dark, banner-light, social, mark")
