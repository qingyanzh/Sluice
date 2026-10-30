// Draws the Sluice app icon (three staggered streams on an off-white tile) and writes an .iconset.
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
        ctx.drawLinearGradient(gradient([rgb(0.905, 0.918, 0.94), rgb(0.975, 0.98, 0.988), rgb(1, 1, 1)], [0, 0.55, 1]),
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

        // The mark: three staggered streams, flowing left to right. Two are graphite;
        // they deepen from graphite through slate into the accent.
        func capsule(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat) -> CGPath {
            CGPath(roundedRect: CGRect(x: x * u, y: y * u, width: w * u, height: 104 * u),
                   cornerWidth: 52 * u, cornerHeight: 52 * u, transform: nil)
        }
        // Same length, same vertical gap (140) and the same horizontal step (60) between streams.
        let streams = [(capsule(242, 600, 420), 0), (capsule(302, 460, 420), 1), (capsule(362, 320, 420), 2)]
        // Three tones, deepening into the accent as the stream moves: graphite, slate, blue.
        let tones: [[NSColor]] = [
            [rgb(0.11, 0.12, 0.14), rgb(0.26, 0.27, 0.30)],
            [rgb(0.36, 0.45, 0.60), rgb(0.52, 0.62, 0.76)],
            [rgb(0.10, 0.40, 1.0), rgb(0.33, 0.68, 1.0)],
        ]
        for (path, i) in streams {
            let accent = i == 2
            ctx.saveGState()
            ctx.setShadow(offset: CGSize(width: 0, height: -8 * u), blur: 20 * u,
                          color: accent ? rgb(0.10, 0.40, 1, 0.35).cgColor : NSColor.black.withAlphaComponent(0.14).cgColor)
            ctx.addPath(path); ctx.setFillColor(NSColor.white.cgColor); ctx.fillPath()
            ctx.restoreGState()
            ctx.saveGState()
            ctx.addPath(path); ctx.clip()
            let colors = tones[i]
            let box = path.boundingBox
            ctx.drawLinearGradient(gradient(colors, [0, 1]), start: CGPoint(x: box.minX, y: box.minY),
                                   end: CGPoint(x: box.maxX, y: box.maxY), options: [])
            // Soft top highlight on each stream.
            ctx.drawLinearGradient(gradient([NSColor.white.withAlphaComponent(0), NSColor.white.withAlphaComponent(0.18)], [0, 1]),
                                   start: CGPoint(x: 0, y: box.midY), end: CGPoint(x: 0, y: box.maxY), options: [])
            ctx.restoreGState()
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
