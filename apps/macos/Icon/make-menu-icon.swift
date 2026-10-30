// Exports Surge's native 28×30 status item silhouette as a monochrome template.
// Usage: swift make-menu-icon.swift <output.png> [Surge.app]
// Surge is only needed to regenerate the asset; the built app bundles the PNG.
import AppKit

guard CommandLine.arguments.count >= 2 else {
    fatalError("Usage: swift make-menu-icon.swift <output.png> [Surge.app]")
}

let appPath = CommandLine.arguments.count >= 3 ? CommandLine.arguments[2] : "/Applications/Surge.app"
guard let bundle = Bundle(url: URL(fileURLWithPath: appPath)),
      let source = bundle.image(forResource: NSImage.Name("status-bar-icon-solid")) else {
    fatalError("Could not read the Surge status bar icon from \(appPath)")
}

let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 28, pixelsHigh: 30,
                              bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                              isPlanar: false, colorSpaceName: .deviceRGB,
                              bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
source.draw(in: CGRect(x: 0, y: 0, width: 28, height: 30))
NSGraphicsContext.restoreGraphicsState()

let data = bitmap.representation(using: .png, properties: [:])!
try data.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
