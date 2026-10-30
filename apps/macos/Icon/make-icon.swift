// Draws the Sluice app icon (a gate with water streaming through it) and writes an .iconset.
// Usage: swift make-icon.swift <out.iconset>
import AppKit

func draw(_ s: CGFloat) -> NSImage {
    NSImage(size: NSSize(width: s, height: s), flipped: false) { _ in
        let ctx = NSGraphicsContext.current!.cgContext
        let u = s / 1024
        // macOS icon grid: 824pt squircle centred in 1024.
        let tile = CGRect(x: 100 * u, y: 100 * u, width: 824 * u, height: 824 * u)
        let shape = CGPath(roundedRect: tile, cornerWidth: 185 * u, cornerHeight: 185 * u, transform: nil)

        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -10 * u), blur: 28 * u, color: NSColor.black.withAlphaComponent(0.28).cgColor)
        ctx.addPath(shape); ctx.setFillColor(NSColor.black.cgColor); ctx.fillPath()
        ctx.restoreGState()

        // Frosted light tile.
        ctx.saveGState()
        ctx.addPath(shape); ctx.clip()
        let space = CGColorSpaceCreateDeviceRGB()
        let bg = CGGradient(colorsSpace: space, colors: [
            NSColor(red: 0.86, green: 0.93, blue: 0.97, alpha: 1).cgColor,
            NSColor(red: 0.99, green: 1.0, blue: 1.0, alpha: 1).cgColor,
        ] as CFArray, locations: [0, 1])!
        ctx.drawLinearGradient(bg, start: CGPoint(x: 0, y: tile.minY), end: CGPoint(x: 0, y: tile.maxY), options: [])
        ctx.restoreGState()
        // Thin top highlight on the rim.
        ctx.addPath(CGPath(roundedRect: tile.insetBy(dx: 2 * u, dy: 2 * u), cornerWidth: 183 * u, cornerHeight: 183 * u, transform: nil))
        ctx.setStrokeColor(NSColor.white.withAlphaComponent(0.9).cgColor); ctx.setLineWidth(4 * u); ctx.strokePath()

        // Glyph: one thick, round-capped stroke tracing an "S", like water winding
        // through a channel. Built as a stroked path so the gradient can fill it.
        let r: CGFloat = 130, cx: CGFloat = 512
        let line = CGMutablePath()
        line.move(to: CGPoint(x: (cx + 150) * u, y: (512 + 2 * r) * u))
        line.addLine(to: CGPoint(x: cx * u, y: (512 + 2 * r) * u))
        line.addArc(center: CGPoint(x: cx * u, y: (512 + r) * u), radius: r * u,
                    startAngle: .pi / 2, endAngle: 3 * .pi / 2, clockwise: false)
        line.addArc(center: CGPoint(x: cx * u, y: (512 - r) * u), radius: r * u,
                    startAngle: .pi / 2, endAngle: -.pi / 2, clockwise: true)
        line.addLine(to: CGPoint(x: (cx - 150) * u, y: (512 - 2 * r) * u))
        let glyph = line.copy(strokingWithWidth: 104 * u, lineCap: .round, lineJoin: .round, miterLimit: 1)
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -14 * u), blur: 34 * u,
                      color: NSColor(red: 0.05, green: 0.35, blue: 0.85, alpha: 0.35).cgColor)
        ctx.addPath(glyph); ctx.setFillColor(NSColor.white.cgColor); ctx.fillPath()
        ctx.restoreGState()
        ctx.saveGState()
        ctx.addPath(glyph); ctx.clip()
        let fg = CGGradient(colorsSpace: space, colors: [
            NSColor(red: 0.08, green: 0.36, blue: 0.95, alpha: 1).cgColor,
            NSColor(red: 0.10, green: 0.78, blue: 0.90, alpha: 1).cgColor,
        ] as CFArray, locations: [0, 1])!
        ctx.drawLinearGradient(fg, start: CGPoint(x: 300 * u, y: 200 * u), end: CGPoint(x: 724 * u, y: 824 * u), options: [])
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
