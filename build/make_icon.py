#!/usr/bin/env python3
"""Generate build/app.ico — the app/installer icon.

Design: a security shield (protection) with a white USB connector mark and a
small green check (scanned/safe). Drawn at high resolution then downscaled into
a multi-size .ico so it stays crisp from 16px taskbar to 256px.

Run:  python build/make_icon.py
Needs: Pillow  (pip install Pillow)
"""

from __future__ import annotations

import os

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "app.ico")

# Colors
SHIELD_TOP = (37, 99, 235)     # blue
SHIELD_BOT = (14, 116, 144)    # teal
SHIELD_EDGE = (255, 255, 255)
USB_COLOR = (255, 255, 255)
CHECK_BG = (34, 197, 94)       # green
CHECK_FG = (255, 255, 255)


def _vgradient(size, top, bot):
    """Vertical gradient image."""
    grad = Image.new("RGB", (1, size), 0)
    for y in range(size):
        t = y / max(1, size - 1)
        grad.putpixel((0, y), tuple(int(top[i] + (bot[i] - top[i]) * t)
                                    for i in range(3)))
    return grad.resize((size, size))


def _shield_mask(size, pad):
    """Rounded shield silhouette as an L mask."""
    m = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(m)
    w = size - 2 * pad
    x0, y0 = pad, pad
    top_r = w * 0.18
    # top rounded rectangle part
    d.rounded_rectangle([x0, y0, x0 + w, y0 + w * 0.62],
                        radius=top_r, fill=255)
    # bottom point (triangle to a rounded tip)
    cx = size / 2
    tip_y = y0 + w * 1.02
    d.polygon([(x0, y0 + w * 0.55),
               (cx, tip_y),
               (x0 + w, y0 + w * 0.55)], fill=255)
    return m


def _draw_usb(d, size):
    """Simple USB connector mark centered on the shield."""
    cx = size / 2
    top = size * 0.30
    bot = size * 0.66
    stem_w = size * 0.055
    # stem
    d.rounded_rectangle([cx - stem_w, top, cx + stem_w, bot],
                        radius=stem_w, fill=USB_COLOR)
    # round head (the plug tip)
    r = size * 0.052
    d.ellipse([cx - r, top - r * 1.6, cx + r, top + r * 0.4], fill=USB_COLOR)
    # three-prong trident base
    base_y = bot
    d.ellipse([cx - size * 0.03, base_y - size * 0.03,
               cx + size * 0.03, base_y + size * 0.03], fill=USB_COLOR)
    # left branch with square tip
    ly = size * 0.46
    d.line([(cx, ly), (cx - size * 0.11, ly - size * 0.04)],
           fill=USB_COLOR, width=max(2, int(size * 0.028)))
    d.rectangle([cx - size * 0.135, ly - size * 0.065,
                 cx - size * 0.085, ly - size * 0.015], fill=USB_COLOR)
    # right branch with round tip
    ry = size * 0.40
    d.line([(cx, ry), (cx + size * 0.11, ry - size * 0.04)],
           fill=USB_COLOR, width=max(2, int(size * 0.028)))
    rr = size * 0.03
    d.ellipse([cx + size * 0.10 - rr, ry - size * 0.04 - rr,
               cx + size * 0.10 + rr, ry - size * 0.04 + rr], fill=USB_COLOR)


def _draw_check(d, size):
    """Green 'scanned/safe' badge bottom-right."""
    r = size * 0.17
    cx, cy = size * 0.72, size * 0.72
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=CHECK_BG,
              outline=(255, 255, 255), width=max(1, int(size * 0.012)))
    w = max(2, int(size * 0.03))
    d.line([(cx - r * 0.45, cy),
            (cx - r * 0.05, cy + r * 0.42),
            (cx + r * 0.55, cy - r * 0.45)],
           fill=CHECK_FG, width=w, joint="curve")


def render(size: int) -> Image.Image:
    S = size * 4  # supersample for smooth edges
    pad = int(S * 0.06)
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    grad = _vgradient(S, SHIELD_TOP, SHIELD_BOT).convert("RGBA")
    mask = _shield_mask(S, pad)
    img.paste(grad, (0, 0), mask)

    # subtle white edge
    edge = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ed = ImageDraw.Draw(edge)
    # draw shield outline by stroking the mask border
    from PIL import ImageFilter
    border = mask.filter(ImageFilter.MaxFilter(9)).point(
        lambda p: 255 if p > 0 else 0)
    inner = mask
    ring = Image.new("L", (S, S), 0)
    ring.paste(255, (0, 0), border)
    ring.paste(0, (0, 0), inner)
    edge.paste(Image.new("RGBA", (S, S), SHIELD_EDGE + (180,)), (0, 0), ring)
    img = Image.alpha_composite(img, edge)

    d = ImageDraw.Draw(img)
    _draw_usb(d, S)
    _draw_check(d, S)

    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    sizes = [16, 24, 32, 48, 64, 128, 256]
    base = render(256)
    imgs = [render(s) for s in sizes]
    base.save(OUT, format="ICO",
              sizes=[(s, s) for s in sizes],
              append_images=imgs)
    # also a PNG preview for docs
    base.save(os.path.join(HERE, "app_preview.png"))
    print(f"Wrote {OUT}  ({', '.join(str(s) for s in sizes)} px)")


if __name__ == "__main__":
    main()
