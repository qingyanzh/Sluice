// Draws the Sluice app icon (a glass orb holding water at a calm, held level) and writes an .iconset.
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
        func rgb(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> NSColor { NSColor(red: r, green: g, blue: b, alpha: a) }

        // macOS icon grid: 824pt squircle centred in 1024.
        let tile = CGRect(x: 100 * u, y: 100 * u, width: 824 * u, height: 824 * u)
        let shape = CGPath(roundedRect: tile, cornerWidth: 185 * u, cornerHeight: 185 * u, transform: nil)
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -10 * u), blur: 26 * u, color: NSColor.black.withAlphaComponent(0.22).cgColor)
        ctx.addPath(shape); ctx.setFillColor(NSColor.white.cgColor); ctx.fillPath()
        ctx.restoreGState()
        // Off-white tile, slightly brighter at the top.
        ctx.saveGState()
        ctx.addPath(shape); ctx.clip()
        ctx.drawLinearGradient(gradient([rgb(0.91, 0.925, 0.945), rgb(1, 1, 1)], [0, 1]),
                               start: CGPoint(x: 0, y: tile.minY), end: CGPoint(x: 0, y: tile.maxY), options: [])
        ctx.restoreGState()

        // The mark: a glass orb holding water, its surface one calm wave — a level, held.
        let c = CGPoint(x: 512 * u, y: 512 * u), radius = 300 * u
        let orb = CGPath(ellipseIn: CGRect(x: c.x - radius, y: c.y - radius, width: 2 * radius, height: 2 * radius), transform: nil)

        // Orb shadow on the tile.
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -22 * u), blur: 48 * u, color: rgb(0.05, 0.25, 0.65, 0.30).cgColor)
        ctx.addPath(orb); ctx.setFillColor(NSColor.white.cgColor); ctx.fillPath()
        ctx.restoreGState()

        ctx.saveGState()
        ctx.addPath(orb); ctx.clip()
        // Empty glass: very pale, cool.
        ctx.drawLinearGradient(gradient([rgb(0.86, 0.91, 0.98), rgb(0.97, 0.985, 1)], [0, 1]),
                               start: CGPoint(x: 0, y: c.y - radius), end: CGPoint(x: 0, y: c.y + radius), options: [])
        // Water: below a single wave slightly under the centre.
        let level = c.y - 30 * u
        let water = CGMutablePath()
        water.move(to: CGPoint(x: c.x - radius - 10 * u, y: level))
        water.addCurve(to: CGPoint(x: c.x, y: level),
                       control1: CGPoint(x: c.x - radius * 0.62, y: level + 78 * u),
                       control2: CGPoint(x: c.x - radius * 0.32, y: level + 78 * u))
        water.addCurve(to: CGPoint(x: c.x + radius + 10 * u, y: level),
                       control1: CGPoint(x: c.x + radius * 0.32, y: level - 78 * u),
                       control2: CGPoint(x: c.x + radius * 0.62, y: level - 78 * u))
        water.addLine(to: CGPoint(x: c.x + radius + 10 * u, y: c.y - radius - 10 * u))
        water.addLine(to: CGPoint(x: c.x - radius - 10 * u, y: c.y - radius - 10 * u))
        water.closeSubpath()
        ctx.saveGState()
        ctx.addPath(water); ctx.clip()
        ctx.drawLinearGradient(gradient([rgb(0.04, 0.28, 0.86), rgb(0.16, 0.50, 1.0), rgb(0.42, 0.74, 1.0)], [0, 0.6, 1]),
                               start: CGPoint(x: 0, y: c.y - radius), end: CGPoint(x: 0, y: level + 80 * u), options: [])
        ctx.restoreGState()
        // Crest highlight: a thin bright line along the wave.
        let crest = CGMutablePath()
        crest.move(to: CGPoint(x: c.x - radius, y: level))
        crest.addCurve(to: CGPoint(x: c.x, y: level),
                       control1: CGPoint(x: c.x - radius * 0.62, y: level + 78 * u),
                       control2: CGPoint(x: c.x - radius * 0.32, y: level + 78 * u))
        crest.addCurve(to: CGPoint(x: c.x + radius, y: level),
                       control1: CGPoint(x: c.x + radius * 0.32, y: level - 78 * u),
                       control2: CGPoint(x: c.x + radius * 0.62, y: level - 78 * u))
        ctx.addPath(crest); ctx.setStrokeColor(NSColor.white.withAlphaComponent(0.85).cgColor)
        ctx.setLineWidth(10 * u); ctx.setLineCap(.round); ctx.strokePath()
        // Glass sheen: a soft highlight at the top-left of the orb.
        ctx.drawRadialGradient(gradient([NSColor.white.withAlphaComponent(0.75), NSColor.white.withAlphaComponent(0)], [0, 1]),
                               startCenter: CGPoint(x: c.x - 110 * u, y: c.y + 170 * u), startRadius: 0,
                               endCenter: CGPoint(x: c.x - 110 * u, y: c.y + 170 * u), endRadius: 170 * u, options: [])
        ctx.restoreGState()
        // Rim: a hairline that catches light at the top.
        ctx.saveGState()
        ctx.addPath(orb); ctx.setLineWidth(6 * u); ctx.replacePathWithStrokedPath(); ctx.clip()
        ctx.drawLinearGradient(gradient([rgb(0.10, 0.35, 0.85, 0.6), NSColor.white.withAlphaComponent(0.95)], [0, 1]),
                               start: CGPoint(x: 0, y: c.y - radius), end: CGPoint(x: 0, y: c.y + radius), options: [])
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
