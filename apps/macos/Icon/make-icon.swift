// Draws the Sluice app icon and writes an .iconset: one white stream enters a frosted
// gate and leaves as three coloured routes, on a deep night tile.
// Usage: swift make-icon.swift <out.iconset>
import AppKit

let space = CGColorSpaceCreateDeviceRGB()
func rgb(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> CGColor { CGColor(red: r, green: g, blue: b, alpha: a) }
func grad(_ c: [CGColor], _ l: [CGFloat]? = nil) -> CGGradient {
    CGGradient(colorsSpace: space, colors: c as CFArray, locations: l ?? (0..<c.count).map { CGFloat($0) / CGFloat(c.count - 1) })!
}
func squircle(_ r: CGRect) -> CGPath {
    let p = CGMutablePath(); let n: CGFloat = 4
    for i in 0...360 {
        let t = CGFloat(i) * .pi / 180, c = cos(t), s = sin(t)
        let pt = CGPoint(x: r.midX + r.width / 2 * (c < 0 ? -1 : 1) * pow(abs(c), 2 / n),
                         y: r.midY + r.height / 2 * (s < 0 ? -1 : 1) * pow(abs(s), 2 / n))
        i == 0 ? p.move(to: pt) : p.addLine(to: pt)
    }
    p.closeSubpath(); return p
}
let tile = CGRect(x: 100, y: 100, width: 824, height: 824)
let shape = squircle(tile)

func base(_ ctx: CGContext, _ colors: [CGColor]) {
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 28, color: rgb(0, 0, 0, 0.3))
    ctx.addPath(shape); ctx.setFillColor(colors[0]); ctx.fillPath()
    ctx.restoreGState()
    ctx.saveGState(); ctx.addPath(shape); ctx.clip()
    ctx.drawLinearGradient(grad(colors), start: CGPoint(x: 200, y: 924), end: CGPoint(x: 824, y: 100), options: [])
    ctx.restoreGState()
}
func rim(_ ctx: CGContext) {
    ctx.saveGState()
    ctx.addPath(shape); ctx.setLineWidth(4); ctx.replacePathWithStrokedPath(); ctx.clip()
    ctx.drawLinearGradient(grad([rgb(1, 1, 1, 0.45), rgb(1, 1, 1, 0.05)]), start: CGPoint(x: 0, y: 924), end: CGPoint(x: 0, y: 100), options: [])
    ctx.restoreGState()
}
/// Strokes `path` and fills the stroke with a gradient from `a` to `b`.
func ribbon(_ ctx: CGContext, _ path: CGPath, width: CGFloat, _ colors: [CGColor], from: CGPoint, to: CGPoint, glow: CGColor? = nil) {
    let stroked = path.copy(strokingWithWidth: width, lineCap: .round, lineJoin: .round, miterLimit: 10)
    if let glow {
        ctx.saveGState(); ctx.setShadow(offset: CGSize(width: 0, height: -10), blur: 30, color: glow)
        ctx.addPath(stroked); ctx.setFillColor(colors.last!); ctx.fillPath(); ctx.restoreGState()
    }
    ctx.saveGState(); ctx.addPath(stroked); ctx.clip()
    ctx.drawLinearGradient(grad(colors), start: from, end: to, options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
    // Glossy top light.
    let box = stroked.boundingBox
    ctx.drawLinearGradient(grad([rgb(1, 1, 1, 0), rgb(1, 1, 1, 0.22)]), start: CGPoint(x: 0, y: box.midY), end: CGPoint(x: 0, y: box.maxY), options: [])
    ctx.restoreGState()
}

/// The mark: a stream, a gate, three routes.
func drawIcon(_ ctx: CGContext) {
    base(ctx, [rgb(0.11, 0.13, 0.33), rgb(0.04, 0.05, 0.15)])
    ctx.saveGState(); ctx.addPath(shape); ctx.clip()
    ctx.drawRadialGradient(grad([rgb(0.35, 0.50, 1, 0.50), rgb(0.35, 0.50, 1, 0)]), startCenter: CGPoint(x: 470, y: 512), startRadius: 0,
                           endCenter: CGPoint(x: 470, y: 512), endRadius: 380, options: [])
    ctx.restoreGState()
    let gx: CGFloat = 440
    // Outer routes first, so the straight middle route sits on top where they meet.
    let routes: [(CGFloat, [CGColor])] = [(712, [rgb(0.40, 0.98, 0.95), rgb(0.12, 0.80, 0.92)]),
                                          (312, [rgb(0.75, 0.60, 1), rgb(0.55, 0.34, 0.98)]),
                                          (512, [rgb(0.50, 0.75, 1), rgb(0.22, 0.52, 1)])]
    // Routes first, so they emerge from behind the gate.
    for (y, c) in routes {
        let p = CGMutablePath(); p.move(to: CGPoint(x: gx, y: 512))
        if y == 512 { p.addLine(to: CGPoint(x: 800, y: y)) } else {
            p.addCurve(to: CGPoint(x: 800, y: y), control1: CGPoint(x: 610, y: 512), control2: CGPoint(x: 590, y: y))
        }
        ribbon(ctx, p, width: 76, c, from: CGPoint(x: gx, y: 0), to: CGPoint(x: 800, y: 0), glow: c[1].copy(alpha: 0.65))
    }
    let trunk = CGMutablePath(); trunk.move(to: CGPoint(x: 224, y: 512)); trunk.addLine(to: CGPoint(x: gx - 26, y: 512))
    ribbon(ctx, trunk, width: 112, [rgb(0.80, 0.88, 1), rgb(1, 1, 1)], from: CGPoint(x: 224, y: 0), to: CGPoint(x: gx, y: 0), glow: rgb(0.6, 0.8, 1, 0.55))
    // The gate: a short frosted slab standing across the stream.
    let slab = CGPath(roundedRect: CGRect(x: gx - 34, y: 512 - 150, width: 68, height: 300), cornerWidth: 34, cornerHeight: 34, transform: nil)
    ctx.saveGState(); ctx.setShadow(offset: CGSize(width: 6, height: -10), blur: 26, color: rgb(0, 0, 0.1, 0.55))
    ctx.addPath(slab); ctx.setFillColor(rgb(1, 1, 1)); ctx.fillPath(); ctx.restoreGState()
    ctx.saveGState(); ctx.addPath(slab); ctx.clip()
    ctx.drawLinearGradient(grad([rgb(1, 1, 1), rgb(0.80, 0.85, 0.96)]), start: CGPoint(x: gx - 34, y: 0), end: CGPoint(x: gx + 34, y: 0), options: [])
    ctx.drawLinearGradient(grad([rgb(1, 1, 1, 0), rgb(1, 1, 1, 0.6)]), start: CGPoint(x: 0, y: 512), end: CGPoint(x: 0, y: 662), options: [])
    ctx.restoreGState()
    rim(ctx)
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
