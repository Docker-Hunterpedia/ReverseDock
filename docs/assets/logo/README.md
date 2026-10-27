# ReverseDock — logo guidelines

## 1. The logo
- **Idea:** Berth. A container moored in a dock bay: your services, docked behind one front door.
- **Versions:** horizontal (primary) · stacked · symbol · wordmark.
- **Files:** `horizontal-*.svg`, `stacked-*.svg`, `symbol-*.svg`, `wordmark-ink.svg` in this folder; the web icon set is in [`apps/website/public/`](../../../apps/website/public/).
  Use SVG wherever possible; PNGs are for places that refuse SVG.

## 2. Clear space
Keep a clear zone of **one bay height** on every side (the height of the cut in the tile, 31 % of the symbol's height).
It scales with the logo.

## 3. Minimum size
| Version | Screen | Note |
|---|---|---|
| Horizontal | 120 px wide | below that, use the symbol |
| Symbol | 32 px | from 31 px down to 16 px use `symbol-small-*.svg` (wider gaps, square box) |

## 4. Colour
| Name | HEX | RGB | Use |
|---|---|---|---|
| Amber | `#F58F0A` | 245 143 10 | the tile; same as `--rd-accent` |
| Ink | `#1C1917` | 28 25 23 | the box and the wordmark; same as `--rd-accent-ink` |

Approved pairs:
- **Full colour on light** (`*-color.svg`): amber tile, ink box, ink wordmark.
- **Full colour on dark** (`*-color-on-dark.svg`): amber tile and amber box (the bay shows the dark background), white wordmark.
  Never put the ink box on a dark background: it disappears.
- **One colour:** black on light, white on dark, or amber on ink (the app icon).

Print values (CMYK, Pantone) are not set yet; get a printer's match against `#F58F0A` before the first print job.

## 5. Typography
- Wordmark: **Inter Display SemiBold**, tracking −1 %, outlined to paths. Never type the name to rebuild it.
- Website and dashboard text: Inter and JetBrains Mono (see [the design system](../../08-design-system.md)).
- Inter is under the SIL Open Font License 1.1, which allows logo use.

## 6. Don'ts
Don't stretch, rotate or recolour outside the palette. Don't add shadows, outlines, gradients or glows. Don't fill the bay.
Don't move or resize the box. Don't change the spacing between symbol and wordmark. Don't use the ink box on dark backgrounds.

## 7. Contact
Usage questions: contact@oday-bakkour.com. Master files: this folder. The website copies are `apps/website/src/assets/logo.svg` and `logo-dark.svg`.
