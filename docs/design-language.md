# Sluice Flow: design language of the macOS app

Sluice moves traffic the way a sluice moves water: quietly, in one direction,
under control. The interface follows the same idea. It is calm and it gets out
of the way. The only things that stand out are the ones that are active.

All values live in `DS` in `apps/macos/Sources/SluiceApp/Views.swift`. Views use
these tokens and never set their own values.

## Principles

1. **Calm surfaces.** The page is a solid off-white (graphite in dark mode).
   Content sits on white cards with a hairline border and a soft two-layer
   shadow. There are no gradients and no decorative colour behind content.
2. **Glass is for controls.** Liquid Glass (`glassEffect`, `.glass` buttons) is
   used only on things you operate: search, segmented controls, buttons and the
   floating status card. Content is never on glass.
3. **One accent means "active".** The brand blue-violet (`DS.accent`, taken
   from the app icon) appears only on
   what is selected, primary or flowing: the selected sidebar item, the
   selected segment, the primary button and download traffic. Everything else
   is grey. Red is used only for rejects and errors. Green is used only for
   status dots.
4. **The flow mark.** This is the signature element: a short accent capsule
   that marks whatever is active. It sits under the selected segment and beside
   the selected request. When the selection moves, the mark slides with it.
5. **Icon tiles.** Every symbol that names a thing (sidebar items, feature
   cards, policy groups, nodes, facts, empty states) sits in an `IconTile`: a
   continuous rounded square at 30% corner radius. At rest it is a quiet grey
   tile with an outline glyph. When on, it fills with the accent and the glyph
   turns white and filled. Site initials (`Monogram`) use the same tile.
6. **Capsule geometry.** Everything interactive is a capsule: buttons, fields,
   segments and progress bars. Cards use a 14pt continuous corner and tiles use
   12pt. Nothing has a square corner.
7. **One spring.** All motion uses `DS.spring` (response 0.32, damping 0.82):
   - Pressed surfaces sink to 97%.
   - Tiles lift on hover.
   - Selections slide between items.
   - Numbers roll when they change.
   - Symbols bounce or swap.
   - Panes cross-fade with an 8pt rise.
   - Cards enter one after another (`entrance`): they rise 14pt, sharpen
     from a slight blur and settle, each 45ms after the last.
8. **One type scale.** SF Pro at fixed steps. Figures use medium weight with
   monospaced digits.

   | Token     | Size and weight | Used for              |
   |-----------|-----------------|-----------------------|
   | `title`   | 26 bold         | pane titles           |
   | `display` | 22 semibold     | status                |
   | `heading` | 14 semibold     | card and tile names   |
   | `label`   | 13              | body text             |
   | `small`   | 12              | descriptions          |
   | `caption` | 11 semibold     | metadata              |

## Contrast

Supporting text uses `DS.ink2` (72% of the primary colour) and metadata
`DS.ink3` (56%), both darker than the system secondary and tertiary styles.
Secondary buttons (`SecondaryCapsuleStyle`) have a surface fill, a 1pt
`DS.stroke` border and full-strength text, so they never read as disabled;
disabled controls fade to 40% and say why in their help text.
Pane titles are 26pt bold, figures are semibold, and captions are semibold,
so the key value in every card reads first.

## State colours

One grammar, tokens in `DS`: blue (`accent`) is action, selection and the
current page; green (`ok`) is confirmed working; orange (`warn`) is attention
or an inconsistent state; red (`fail`) is failure; grey (`off`) is off,
unconfigured or no data. No other colour carries meaning. Icon tiles are flat
(no glow), containers have a hairline and one faint shadow, and the accent fill
is kept for the primary button.

## Layout

- Home reads in three tiers: state and its one main action; how traffic leaves
  (出站模式 · 当前节点 · 系统代理, each opening the pane that changes it);
  traffic and requests. The sidebar's start button is a quiet round icon.
- Content stops at `DS.maxContentWidth`; lists size to their rows.
- Every empty pane uses `EmptyState`: an illustration, the reason, one primary
  action and at most one secondary.
- 设置 sits apart at the bottom of the sidebar.

## States and failures

- The core's state reads the same everywhere: the activity hero, the toolbar
  pills, the policy and requests empty states, and the rule test. While
  stopped, every place that needs the core says so and offers 启动 Sluice.
- A setting that is on but not working is a warning, not a success: the system
  proxy pointing at a stopped core is an orange banner on every pane, with
  启动 and 关闭系统代理 right there.
- Missing setup is stated with its effect and its fix ("还没有代理节点 … 所有流量
  都会直连", with 添加节点 / 添加订阅 opening the sheet directly).
- Every error has a plain Chinese first line (what happened and what to do);
  the core's own message folds under 详细信息; format errors show a correct
  example with a copy button (`ErrorText`).

## Appearance

The app follows the system appearance by default; 设置 › 外观 can pin it to
light or dark. Every colour is dynamic: tokens in `DS` resolve per appearance,
and the config editor uses the system label colours, never a colour with a
fixed alpha, so nothing turns grey-on-grey in dark mode.

## Icon

The icon is five bars on a light lavender tile. They share a left edge and
their lengths swell to the longest in the middle, then fall away. Every bar
uses the same blue-to-violet gradient, with a white outline and a soft
coloured shadow. The tile has a bright inner border and a glow at the top
left.

It uses the same vocabulary as the interface: capsule shapes, a calm light
surface and a single hue.

The icon is generated by `apps/macos/Icon/make-icon.swift`:

```bash
swift apps/macos/Icon/make-icon.swift /tmp/Sluice.iconset
iconutil -c icns /tmp/Sluice.iconset -o apps/macos/Icon/Sluice.icns
```
