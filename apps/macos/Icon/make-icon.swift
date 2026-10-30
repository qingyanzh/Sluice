// Draws the Sluice app icon (a luminous S-shaped water channel on graphite) and writes an .iconset.
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
        // macOS icon grid: 824pt squircle centred in 1024.
        let tile = CGRect(x: 100 * u, y: 100 * u, width: 824 * u, height: 824 * u)
        let shape = CGPath(roundedRect: tile, cornerWidth: 185 * u, cornerHeight: 185 * u, transform: nil)

        // Drop shadow.
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -12 * u), blur: 30 * u, color: NSColor.black.withAlphaComponent(0.35).cgColor)
        ctx.addPath(shape); ctx.setFillColor(NSColor.black.cgColor); ctx.fillPath()
        ctx.restoreGState()

        // Graphite tile with a soft sheen from the top.
        ctx.saveGState()
        ctx.addPath(shape); ctx.clip()
        ctx.drawLinearGradient(gradient([NSColor(red: 0.07, green: 0.075, blue: 0.09, alpha: 1),
                                         NSColor(red: 0.17, green: 0.18, blue: 0.21, alpha: 1)], [0, 1]),
                               start: CGPoint(x: 0, y: tile.minY), end: CGPoint(x: 0, y: tile.maxY), options: [])
        ctx.drawRadialGradient(gradient([NSColor.white.withAlphaComponent(0.10), NSColor.white.withAlphaComponent(0)], [0, 1]),
                               startCenter: CGPoint(x: 512 * u, y: 980 * u), startRadius: 0,
                               endCenter: CGPoint(x: 512 * u, y: 980 * u), endRadius: 620 * u, options: [])
        ctx.restoreGState()
        // Hairline rim, brighter at the top.
        ctx.saveGState()
        ctx.addPath(CGPath(roundedRect: tile.insetBy(dx: 1.5 * u, dy: 1.5 * u), cornerWidth: 184 * u, cornerHeight: 184 * u, transform: nil))
        ctx.setLineWidth(3 * u); ctx.replacePathWithStrokedPath(); ctx.clip()
        ctx.drawLinearGradient(gradient([NSColor.white.withAlphaComponent(0.04), NSColor.white.withAlphaComponent(0.28)], [0, 1]),
                               start: CGPoint(x: 0, y: tile.minY), end: CGPoint(x: 0, y: tile.maxY), options: [])
        ctx.restoreGState()

        // Glyph: an "S" channel of water, one round-capped stroke.
        let r: CGFloat = 122, cx: CGFloat = 512
        let line = CGMutablePath()
        line.move(to: CGPoint(x: (cx + 140) * u, y: (512 + 2 * r) * u))
        line.addLine(to: CGPoint(x: cx * u, y: (512 + 2 * r) * u))
        line.addArc(center: CGPoint(x: cx * u, y: (512 + r) * u), radius: r * u,
                    startAngle: .pi / 2, endAngle: 3 * .pi / 2, clockwise: false)
        line.addArc(center: CGPoint(x: cx * u, y: (512 - r) * u), radius: r * u,
                    startAngle: .pi / 2, endAngle: -.pi / 2, clockwise: true)
        line.addLine(to: CGPoint(x: (cx - 140) * u, y: (512 - 2 * r) * u))
        let glyph = line.copy(strokingWithWidth: 92 * u, lineCap: .round, lineJoin: .round, miterLimit: 1)

        // Accent glow beneath the glyph.
        ctx.saveGState()
        ctx.setShadow(offset: .zero, blur: 60 * u, color: NSColor(red: 0.2, green: 0.55, blue: 1, alpha: 0.55).cgColor)
        ctx.addPath(glyph); ctx.setFillColor(NSColor(red: 0.2, green: 0.5, blue: 1, alpha: 1).cgColor); ctx.fillPath()
        ctx.restoreGState()
        // Body: ice at the top flowing into deep accent blue.
        ctx.saveGState()
        ctx.addPath(glyph); ctx.clip()
        ctx.drawLinearGradient(gradient([NSColor(red: 0.10, green: 0.38, blue: 1.0, alpha: 1),
                                         NSColor(red: 0.35, green: 0.70, blue: 1.0, alpha: 1),
                                         NSColor(red: 0.88, green: 0.96, blue: 1.0, alpha: 1)], [0, 0.55, 1]),
                               start: CGPoint(x: 0, y: 220 * u), end: CGPoint(x: 0, y: 800 * u), options: [])
        // Specular highlight: a thin bright line riding the upper edge of the stroke.
        var shift = CGAffineTransform(translationX: -10 * u, y: 16 * u)
        ctx.addPath(line.copy(strokingWithWidth: 18 * u, lineCap: .round, lineJoin: .round, miterLimit: 1).copy(using: &shift)!)
        ctx.setFillColor(NSColor.white.withAlphaComponent(0.45).cgColor); ctx.fillPath()
        ctx.restoreGState()
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
