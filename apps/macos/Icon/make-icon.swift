// Draws the Sluice app icon and writes an .iconset: five outlined blue-violet bars
// on a light lavender tile.
// Usage: swift make-icon.swift <out.iconset>
import AppKit

let space = CGColorSpaceCreateDeviceRGB()
func rgb(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> CGColor { CGColor(red: r, green: g, blue: b, alpha: a) }
func grad(_ c: [CGColor], _ l: [CGFloat]? = nil) -> CGGradient {
    CGGradient(colorsSpace: space, colors: c as CFArray, locations: l ?? (0..<c.count).map { CGFloat($0) / CGFloat(c.count - 1) })!
}
func squircle(_ r: CGRect, n: CGFloat = 4) -> CGPath {
    let p = CGMutablePath()
    for i in 0...720 {
        let t = CGFloat(i) * .pi / 360, c = cos(t), s = sin(t)
        let pt = CGPoint(x: r.midX + r.width / 2 * (c < 0 ? -1 : 1) * pow(abs(c), 2 / n),
                         y: r.midY + r.height / 2 * (s < 0 ? -1 : 1) * pow(abs(s), 2 / n))
        i == 0 ? p.move(to: pt) : p.addLine(to: pt)
    }
    p.closeSubpath(); return p
}
let tile = CGRect(x: 100, y: 100, width: 824, height: 824)
let shape = squircle(tile)
func newCtx() -> CGContext {
    CGContext(data: nil, width: 1024, height: 1024, bitsPerComponent: 8, bytesPerRow: 0, space: space,
              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
}
func base(_ ctx: CGContext, top: CGColor, bottom: CGColor) {
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 28, color: rgb(0, 0, 0, 0.28))
    ctx.addPath(shape); ctx.setFillColor(bottom); ctx.fillPath()
    ctx.restoreGState()
    ctx.saveGState(); ctx.addPath(shape); ctx.clip()
    ctx.drawLinearGradient(grad([top, bottom]), start: CGPoint(x: 0, y: 924), end: CGPoint(x: 0, y: 100), options: [])
    ctx.restoreGState()
}
/// Light lavender tile with a bright inner border, the canvas for all three.
func lavender(_ ctx: CGContext) {
    base(ctx, top: rgb(0.98, 0.985, 1), bottom: rgb(0.86, 0.88, 0.98))
    ctx.saveGState(); ctx.addPath(shape); ctx.clip()
    ctx.drawRadialGradient(grad([rgb(1, 1, 1, 0.9), rgb(1, 1, 1, 0)]), startCenter: CGPoint(x: 380, y: 860), startRadius: 0,
                           endCenter: CGPoint(x: 380, y: 860), endRadius: 600, options: [])
    ctx.restoreGState()
    ctx.saveGState(); ctx.addPath(squircle(tile.insetBy(dx: 10, dy: 10))); ctx.setLineWidth(10); ctx.replacePathWithStrokedPath(); ctx.clip()
    ctx.setFillColor(rgb(1, 1, 1, 0.75)); ctx.fill(tile); ctx.restoreGState()
}
/// One bar: white outline, single-hue gradient, soft coloured shadow.
func bar(_ ctx: CGContext, _ r: CGRect, vertical: Bool = false) {
    let rad = min(r.width, r.height) / 2
    let p = CGPath(roundedRect: r, cornerWidth: rad, cornerHeight: rad, transform: nil)
    let outline = CGPath(roundedRect: r.insetBy(dx: -7, dy: -7), cornerWidth: rad + 7, cornerHeight: rad + 7, transform: nil)
    ctx.saveGState(); ctx.setShadow(offset: CGSize(width: 0, height: -10), blur: 22, color: rgb(0.25, 0.25, 0.85, 0.30))
    ctx.addPath(outline); ctx.setFillColor(rgb(1, 1, 1)); ctx.fillPath(); ctx.restoreGState()
    ctx.saveGState(); ctx.addPath(p); ctx.clip()
    let a = vertical ? CGPoint(x: 0, y: r.minY) : CGPoint(x: r.minX, y: 0)
    let b = vertical ? CGPoint(x: 0, y: r.maxY) : CGPoint(x: r.maxX, y: 0)
    ctx.drawLinearGradient(grad([rgb(0.20, 0.62, 1), rgb(0.22, 0.38, 1), rgb(0.30, 0.20, 0.95)]), start: a, end: b, options: [])
    // inner top shade, like Surge's engraved look
    ctx.drawLinearGradient(grad([rgb(1, 1, 1, 0.0), rgb(1, 1, 1, 0.0), rgb(0.1, 0.1, 0.4, 0.18)], [0, 0.7, 1]), start: CGPoint(x: 0, y: r.minY), end: CGPoint(x: 0, y: r.maxY), options: [])
    ctx.restoreGState()
}

/// The mark: five bars, left-aligned, whose lengths swell to the middle and fall away.
func drawIcon(_ ctx: CGContext) {
    lavender(ctx)
    let h: CGFloat = 66, gap: CGFloat = 34
    let rows: [(CGFloat, CGFloat)] = [(250, 160), (250, 300), (250, 520), (330, 360), (450, 120)]
    let span = CGFloat(rows.count) * h + CGFloat(rows.count - 1) * gap
    for (i, (x, w)) in rows.enumerated() {
        bar(ctx, CGRect(x: x + 20, y: 512 + span / 2 - h - CGFloat(i) * (h + gap), width: w, height: h))
    }
}
let out = URL(fileURLWithPath: CommandLine.arguments[1])
try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
for base in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let px = base * scale
        let ctx = CGContext(data: nil, width: px, height: px, bitsPerComponent: 8, bytesPerRow: 0, space: space,
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        ctx.scaleBy(x: CGFloat(px) / 1024, y: CGFloat(px) / 1024)
        drawIcon(ctx)
        let name = scale == 1 ? "icon_\(base)x\(base).png" : "icon_\(base)x\(base)@2x.png"
        try! NSBitmapImageRep(cgImage: ctx.makeImage()!).representation(using: .png, properties: [:])!
            .write(to: out.appendingPathComponent(name))
    }
}
