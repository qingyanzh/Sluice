// Draws the Sluice app icon (five staggered streams on an off-white tile) and writes an .iconset.
// Usage: swift make-icon.swift <out.iconset>
import AppKit

func draw(_ s: CGFloat) -> NSImage {
    NSImage(size: NSSize(width: s, height: s), flipped: false) { _ in
        let ctx = NSGraphicsContext.current!.cgContext
        let u = s / 1024
        let space = CGColorSpaceCreateDeviceRGB()
        func gradient(_ colors: [NSColor], _ locations: [CGFloat]) -> CGGradient {
            CGGradient(colorsSpace: space, colors: colors.map(\.cgColor) as CFArray, locations: locations)!
        }
        // Continuous-corner tile (superellipse), the shape macOS uses for app icons.
        func squircle(_ r: CGRect) -> CGPath {
            let path = CGMutablePath()
            let n: CGFloat = 4, a = r.width / 2, b = r.height / 2
            for i in 0...360 {
                let t = CGFloat(i) * .pi / 180
                let c = cos(t), s = sin(t)
                let x = r.midX + a * (c < 0 ? -1 : 1) * pow(abs(c), 2 / n)
                let y = r.midY + b * (s < 0 ? -1 : 1) * pow(abs(s), 2 / n)
                i == 0 ? path.move(to: CGPoint(x: x, y: y)) : path.addLine(to: CGPoint(x: x, y: y))
            }
            path.closeSubpath()
            return path
        }
        func rgb(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> NSColor { NSColor(red: r, green: g, blue: b, alpha: a) }

        // macOS icon grid: 824pt squircle centred in 1024.
        let tile = CGRect(x: 100 * u, y: 100 * u, width: 824 * u, height: 824 * u)
        let shape = squircle(tile)
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -10 * u), blur: 26 * u, color: NSColor.black.withAlphaComponent(0.22).cgColor)
        ctx.addPath(shape); ctx.setFillColor(NSColor.white.cgColor); ctx.fillPath()
        ctx.restoreGState()
        // Off-white tile, slightly brighter at the top.
        ctx.saveGState()
        ctx.addPath(shape); ctx.clip()
        ctx.drawLinearGradient(gradient([rgb(0.90, 0.925, 0.965), rgb(0.97, 0.978, 0.99), rgb(1, 1, 1)], [0, 0.55, 1]),
                               start: CGPoint(x: 0, y: tile.minY), end: CGPoint(x: 0, y: tile.maxY), options: [])
        // A soft pool of light behind the mark, so the streams sit in depth rather than on a flat card.
        ctx.drawRadialGradient(gradient([rgb(0.80, 0.87, 1, 0.35), rgb(0.80, 0.87, 1, 0)], [0, 1]),
                               startCenter: CGPoint(x: 560 * u, y: 470 * u), startRadius: 0,
                               endCenter: CGPoint(x: 560 * u, y: 470 * u), endRadius: 380 * u, options: [])
        ctx.restoreGState()
        // Hairline rim: bright on top, a touch darker below, like a machined edge.
        ctx.saveGState()
        ctx.addPath(shape); ctx.setLineWidth(3 * u); ctx.replacePathWithStrokedPath(); ctx.clip()
        ctx.drawLinearGradient(gradient([rgb(0, 0, 0, 0.10), rgb(1, 1, 1, 1)], [0, 1]),
                               start: CGPoint(x: 0, y: tile.minY), end: CGPoint(x: 0, y: tile.maxY), options: [])
        ctx.restoreGState()

        // The mark: five streams of different lengths, set like water moving at different
        // speeds. Each row is one or two capsules given as (start x, length) on the 1024 grid.
        let h: CGFloat = 72, gap: CGFloat = 34
        let rows: [[(CGFloat, CGFloat)]] = [[(420, 340)], [(300, 420)], [(220, 560)], [(340, 400)], [(460, 260)]]
        let span = CGFloat(rows.count) * h + CGFloat(rows.count - 1) * gap
        // Colour runs through the set: cyan at the top, through blue, into indigo at the bottom.
        let ramp: [(CGFloat, CGFloat, CGFloat)] = [(0.16, 0.80, 0.92), (0.13, 0.62, 1.0), (0.18, 0.46, 1.0), (0.32, 0.36, 0.98), (0.45, 0.30, 0.92)]
        for (i, row) in rows.enumerated() {
            let y = 512 + span / 2 - h - CGFloat(i) * (h + gap)
            let (r, g, b) = ramp[i]
            for (k, (x, w)) in row.enumerated() where w > 0 {
                let rect = CGRect(x: x * u, y: y * u, width: w * u, height: h * u)
                let path = CGPath(roundedRect: rect, cornerWidth: h / 2 * u, cornerHeight: h / 2 * u, transform: nil)
                // A trailing droplet is a little lighter than the stream it follows.
                let a: CGFloat = k == 0 ? 1 : 0.55
                ctx.saveGState()
                ctx.setShadow(offset: CGSize(width: 0, height: -7 * u), blur: 18 * u, color: rgb(r, g, b, 0.36 * a).cgColor)
                ctx.addPath(path); ctx.setFillColor(rgb(r, g, b, a).cgColor); ctx.fillPath()
                ctx.restoreGState()
                ctx.saveGState()
                ctx.addPath(path); ctx.clip()
                ctx.setAlpha(a)
                // Lighter at the head of the stream, full colour at its tail.
                ctx.drawLinearGradient(gradient([rgb(min(r + 0.22, 1), min(g + 0.18, 1), b, 1), rgb(r, g, b)], [0, 1]),
                                       start: CGPoint(x: rect.minX, y: 0), end: CGPoint(x: rect.maxX, y: 0), options: [])
                // Soft top highlight and a faint lower edge give each stream a little volume.
                ctx.drawLinearGradient(gradient([rgb(0, 0, 0, 0.08), rgb(1, 1, 1, 0), rgb(1, 1, 1, 0.28)], [0, 0.45, 1]),
                                       start: CGPoint(x: 0, y: rect.minY), end: CGPoint(x: 0, y: rect.maxY), options: [])
                ctx.restoreGState()
            }
        }
        return true
    }
}

let out = URL(fileURLWithPath: CommandLine.arguments[1])
try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
for base in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let px = CGFloat(base * scale)
        let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(px), pixelsHigh: Int(px), bitsPerSample: 8,
                                   samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
        draw(px).draw(in: NSRect(x: 0, y: 0, width: px, height: px))
        NSGraphicsContext.restoreGraphicsState()
        let name = scale == 1 ? "icon_\(base)x\(base).png" : "icon_\(base)x\(base)@2x.png"
        try! rep.representation(using: .png, properties: [:])!.write(to: out.appendingPathComponent(name))
    }
}
