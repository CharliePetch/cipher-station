# Cipher Brand Package

A portable version of [`DESIGN.md`](../website/DESIGN.md) for products that
aren't the Next.js sites — CipherVault, CipherFrame, cipher_station itself,
and anything future. DESIGN.md is the source of truth for web work and stays
in CSS custom properties; this file exists because a SwiftUI app can't
`@import` that file, so the same system is restated here in hex and Swift.

**The one-line philosophy:** calm, minimal, and typographic — content leads,
chrome recedes, and one teal accent does all the pointing. Every Cipher
product should be recognizable as the same family without looking identical —
same colour, same mark, same restraint; different content.

---

## 1. Color

One accent. Nothing else gets color, except `--danger` for states where
losing the signal would cost the reader real information (a failed install, a
station that's down) — never for emphasis, never a second accent.

| Token | Light | Dark | Role |
|---|---|---|---|
| Background | `#fdfdfc` | `#0e1111` | Page / screen background. Never pure white or pure black. |
| Foreground | `#1a1a1a` | `#e8eae9` | Primary text |
| Muted | `#6b7075` | `#9aa3a1` | Secondary text |
| **Accent (teal)** | `#0f766e` | `#2dd4bf` | Links, buttons, selection, the mark |
| Accent soft | `#0f766e` @ 8% | `#2dd4bf` @ 10% | Chip/pill backgrounds, hover fills |
| Border | `#e7e5e0` | `#242928` | Hairlines, card outlines |
| Card | `#ffffff` | `#161a1a` | Surfaces raised off the background |
| Danger | `#b91c1c` | `#f87171` | Failure states only |

Dark mode isn't a tint of light mode — the accent itself shifts (`#0f766e` →
`#2dd4bf`) because a muted teal that reads calmly on off-white goes muddy on
near-black; the brighter value is the same hue doing the same job at the
contrast dark mode needs.

### SwiftUI

```swift
extension Color {
    static let cipherBackground = Color("CipherBackground") // #fdfdfc / #0e1111
    static let cipherForeground = Color("CipherForeground") // #1a1a1a / #e8eae9
    static let cipherMuted      = Color("CipherMuted")      // #6b7075 / #9aa3a1
    static let cipherAccent     = Color("CipherAccent")     // #0f766e / #2dd4bf
    static let cipherBorder     = Color("CipherBorder")     // #e7e5e0 / #242928
    static let cipherCard       = Color("CipherCard")       // #ffffff / #161a1a
    static let cipherDanger     = Color("CipherDanger")     // #b91c1c / #f87171
}
```

Define these as Color Set assets in `Assets.xcassets` with Any/Dark
appearances set to the hex pairs above — that gets automatic light/dark
switching for free, the same "respect the system, no manual mode-watching"
behavior the websites get from `prefers-color-scheme`. Don't hardcode hex
literals at call sites; a Color Set is this system's equivalent of a CSS
custom property.

### Rules

- One accent per product. Teal is the brand.
- No gradients, no shadows for decoration. Hierarchy comes from type scale,
  spacing, and hairlines — a card is a 1pt border, not a drop shadow.
- Chips/tags: accent-soft fill + accent text, or a plain hairline border for
  neutral items.

## 2. Typography

| Context | Typeface |
|---|---|
| Web (Next.js sites) | **Geist Sans** / **Geist Mono**, via `next/font/google` |
| Native iOS/macOS apps | **San Francisco** (the system font — `.default` / `-apple-system`) |

Don't bundle Geist into a native app to chase pixel parity with the websites.
A native app that reaches for the platform's own system font *feels* native —
correct sizing, correct Dynamic Type behavior, no custom-font flash on
launch — and that reads as more "Cipher" than a web typeface pasted into a
context it wasn't meant for. Brand consistency here comes from color, the
mark, and restraint, not from forcing one font stack everywhere.

- Headings: bold, tight tracking. The largest thing on a screen is the title,
  not a hero image.
- Section labels: small caps-style — `SF Footnote`/`Caption`, semibold,
  uppercase, wide tracking, in the accent color.
- Body: relaxed line height, muted color for secondary text.
- Monospace (IDs, keys, fingerprints, technical detail): Geist Mono on the
  web; SF Mono natively.

## 3. Logo

`logo/cipher-mark.svg` — a node orbited by a ring. It reads as "a network,
and a station on it," which is the actual protocol shape, not decoration.

- **One mark, one color.** Never a gradient fill, never two-tone, never
  recolored to match a season or a campaign.
- **Never stretched.** The ellipse's rotation and aspect ratio are the mark —
  scale uniformly only.
- **Clear space:** leave at least half the mark's own height empty on every
  side. It's meant to sit alone, not get crowded by a wordmark or nav items
  pressed up against it.
- **Minimum size:** 20px / 20pt. Below that the ring's stroke and the node
  blur together — use `logo/cipher-mark-filled.svg` (solid ring, no thin
  stroke) instead of shrinking the outline version further.
- **On dark vs. light:** the mark is `currentColor` — light backgrounds get
  the light-mode accent (`#0f766e`), dark backgrounds the dark-mode accent
  (`#2dd4bf`). Don't put the light-mode teal on a dark background; it reads
  muddy, which is exactly why DESIGN.md's dark palette shifts the accent
  brighter in the first place (§1).
- **Wordmark lockup:** `logo/cipher-wordmark.svg`, or on the web the real
  `<CipherMark />` + text set in Geist Sans (`components/Logo.tsx`) — prefer
  the live component over the SVG lockup whenever the context can render one,
  since the SVG substitutes a system font for portability.

## 4. App icon

One visual system, one glyph per product — the same relationship the mark has
to the sites: shared shape and color, different content.

- **Canvas:** flat `#0e1111` (dark-mode background, not a new color), full
  bleed, no pre-rounded corners. iOS masks the shape itself; a baked-in radius
  either doubles up or shows as a hairline behind the system mask.
- **Mark:** the ring and node in `#2dd4bf` (dark-mode accent), flat fill, no
  glow or gradient. The previous icon was a leftover from before the rebrand —
  blue, not teal, with a decorative radial glow — which is the exact "off-
  system color + decoration DESIGN.md forbids" problem this package exists to
  prevent from recurring per-app.
- **Per-app identity:** a small glyph knocked out of the node in the
  background color. Keep new glyphs to this same treatment — one flat shape,
  cut from the node, no added color — rather than inventing a new visual
  language per app.

| Product | Glyph | File |
|---|---|---|
| Cipher (station / generic) | plain node, no glyph | `icons/cipher-icon.svg` / `.png` |
| CipherVault | keyhole | `icons/ciphervault-icon.svg` / `.png` |
| CipherFrame | stacked frames | `icons/cipherframe-icon.svg` / `.png` |

**Xcode:** both apps' `Assets.xcassets/AppIcon.appiconset` use the modern
single-entry format — one `1024x1024` PNG, idiom `universal`. Drop the PNG in
and rename it to match the existing `Contents.json` (`AppIcon.png`); no
multi-size iconset generation needed unless a project's `Contents.json` still
uses the legacy per-size-and-scale format, in which case regenerate from the
SVG source with an icon-set tool (e.g. Xcode's own asset catalog importer)
rather than re-drawing by hand.

A new product picks a glyph the same way: one simple shape, silhouette
readable at 40×40pt, cut from the node — not drawn as a whole new icon from
scratch.

## 5. Icons (in-UI, not app icons)

- Inline SVG only, no icon fonts or libraries.
- Outline style: `fill="none" stroke="currentColor" stroke-width="2"
  stroke-linecap="round"`, 24×24 viewBox, rendered ~15–16px. On iOS, SF
  Symbols at a matching weight (`.regular`/`.medium`) are the native
  equivalent — don't hand-draw outline icons that SF Symbols already covers.
- Icons inherit color from their context; never hardcode an icon's fill.
- Arrows in text/links are the character `→`, not a glyph.

## 6. Shape & spacing

| Element | Radius / value |
|---|---|
| Card | 12pt (`rounded-xl`) |
| Button, input | 8pt (`rounded-lg`) |
| Chip / pill | fully rounded |
| Hairline border | 1pt, `--border` |
| Content column (web) | `max-w-3xl` (~768px), 24pt gutters |

Cards are a hairline border on a raised surface color, never a shadow. This
holds on iOS too: a `RoundedRectangle(cornerRadius: 12).stroke(.cipherBorder)`
over `.cipherCard`, not `.shadow()`.

## 7. Interaction & motion

- Hover/press states are color transitions only — muted → foreground, border
  → accent. No scale, no bounce, no springs standing in for hierarchy.
- At most **one** primary (solid-accent) button/action per screen. Everything
  else is bordered or plain text.
- Nothing animates on its own. Motion only in direct response to input.

## 8. Voice

Short, concrete, first person where the product is speaking to one person (a
customer's own dashboard). Numbers over adjectives. State what's true, not
what's impressive — see `PairingPins.tsx` and `RevealSecrets.tsx` in
`cipher-hosting` for the standard this is held to: plain-language disclosure
of exactly what a feature does and doesn't protect against, not marketing
softened into vagueness.

---

## Package contents

```
brand/
├── BRAND.md                       this file
├── logo/
│   ├── cipher-mark.svg            outline mark, currentColor — web/UI use
│   ├── cipher-mark-filled.svg     solid mark — favicons, small/print use
│   └── cipher-wordmark.svg        mark + wordmark lockup, portable SVG
└── icons/
    ├── cipher-icon.svg / .png     master app icon (1024×1024)
    ├── ciphervault-icon.svg / .png
    └── cipherframe-icon.svg / .png
```

The `.svg` files are the editable source; the `.png` files are the exact
1024×1024 raster export Xcode's `AppIcon.appiconset` expects and are already
installed into both `CipherVault` and `CipherFrame`.
