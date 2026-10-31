# Sluice Flow: macOS design language

Sluice presents the connection state first, then the route, then live activity.
Keep the interface quiet, readable, and consistent across light and dark mode.
Shared layout, colour, and type tokens live in `DS` in
`apps/macos/Sources/SluiceApp/Views.swift`.

## Layout

- The sidebar is 212 pt wide. Navigation rows are 44 pt tall, with 4 pt between
  rows and 24 pt between groups. Use a plain 17 pt symbol and a 14 pt label;
  the selected row gets a subtle surface, not an icon tile.
- Page gutters are 28 pt. Cards use 20 pt padding, a 14 pt corner radius,
  and 16 pt between peers. Sections use 24 pt of separation.
- The activity page has a state card, a three-part route card, and four equal
  224 pt cards in a two-column grid. At narrow widths the four cards stack.
  Rankings show three items so they stay within the shared card height.
- Settings use two columns of equal-height feature cards. Lists give rows
  enough vertical padding for a 13 pt primary line and readable metadata.
- Content stops at `DS.maxContentWidth` on wide windows. Page headers move
  controls to a second row when needed.

## Type and contrast

Use SF Pro for text and monospaced digits for figures. Large figures use a
medium weight so card labels remain easy to scan.

| Token | Size and weight | Use |
|-------|-----------------|-----|
| `title` | 22 semibold | Page titles |
| `display` | 20 medium | Main state |
| `heading` | 15 semibold | Card titles |
| `navigation` | 14 regular | Sidebar |
| `label` | 14 regular | Body and controls |
| `small` | 13 regular | Descriptions |
| `caption` | 12 medium | Metadata |

Regular controls are 34 pt high, compact controls 28 pt, and primary controls
36 pt. Live dashboard values interpolate between samples with a fixed display
width; unit changes reset interpolation. Reduce Motion disables this animation.
Keep the sidebar state on one line, using a shield icon for root operation.
Subscription usage occupies the full card width; secondary facts wrap into an
adaptive grid below it.

`DS.ink2` is for descriptions and labels. `DS.ink3` is for timestamps,
secondary metadata, and hints. Both are opaque dynamic colours selected for
the current appearance; avoid stacking transparent text over tinted cards.
Search and form placeholders use these inks directly. The configuration
editor applies the same contrast to comments and line numbers. Disabled
controls may fade, while enabled supporting text should remain legible.

## Colour and surfaces

- Use a solid off-white page and white content cards in light mode; deep
  graphite and slightly lighter cards in dark mode. Keep borders and shadows
  quiet. Glass belongs on interactive controls.
- `DS.accent` marks the selected page, active segment, main action, and
  download traffic. Green (`DS.ok`) means working, orange (`DS.warn`) means
  attention, red (`DS.fail`) means failure, and neutral (`DS.off`) means off.
- A system proxy enabled while the core is stopped is a warning in every
  pane, including its status chip in Settings. State colour must reflect the
  effect on connectivity, not just the switch position.
- Use `DS.spring` for pressed and selection motion. Respect the system Reduce
  Motion preference for pane transitions.

## Browsing and editing

- Search fields use ⌘F to focus and Esc to clear. Empty filtered lists offer
  a clear action. Request updates can be paused without pausing traffic.
- Active connections use aligned destination, upload, and download columns when
  the list is at least 620 pt wide. Each traffic column shows rate above cumulative
  bytes. Narrow lists put both directions together below the destination. Keep
  row separators, selection, and hover feedback visible; clip scrolling content
  to the list card.
- Nodes show names, protocol, and endpoint metadata. Details do not reveal
  passwords or subscription URL tokens.
- Configuration drafts survive pane navigation. External edits are detected
  before saving, and saved and applied are separate outcomes.
- Policy groups use profile and source disclosures, remembering expansion per
  profile. Inactive profiles are read-only until explicitly switched. Show the
  default egress chain and references separately from presentation order. Imported
  groups can be copied into owned groups; creation offers default or rule usage.
  Adding a node source and importing a complete profile are separate actions.
- Empty states explain why content is unavailable and offer one useful action.
  Running and stopped states should be visually coherent in every pane.

## Menu bar

- The macOS status item uses a monochrome version of Sluice's five-channel mark,
  with three persistent display modes: icon and live speed, icon only, or
  live speed only. Live speed uses Surge's two centred 9 pt rows: upload above
  download, without arrows, decimal KB/s and higher units. Zero traffic shows
  `0 KB/s`. The current outbound mode is a small D/G/R badge on the icon.
- The icon can dim when neither the system proxy nor enhanced mode is enabled.
  These preferences are available in Settings and the status menu.
- The native menu begins with engine state, profile name, and live traffic.
  Start or stop is the first action. Outbound mode and selectable policy
  groups use submenus with checkmarks, followed by system proxy and enhanced
  mode switches.
- Reload and restart are available only when the engine supports them. Main
  window, requests, and current configuration have direct shortcuts below the
  controls.

## Icon

The app icon is generated by `apps/macos/Icon/make-icon.swift` from the
installed Surge app icon. Its five bars, spacing, tile, shadows, and glow
are preserved; only hue and saturation change, producing a pearl and
lagoon palette. The native Surge status-bar silhouette is bundled as a
template image so macOS can tint it for each appearance and connection
state. The deep teal UI accent keeps controls legible in both appearances.
