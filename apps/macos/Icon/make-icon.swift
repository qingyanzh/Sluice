// Recolours Surge's installed icon without changing its geometry or lighting.
// Usage: swift make-icon.swift <out.iconset> [Surge MainIcon.icns]
// The app bundles the generated Sluice.icns; Surge is only needed to regenerate it.
import AppKit
import CoreImage
import CoreImage.CIFilterBuiltins

let arguments = CommandLine.arguments
guard arguments.count >= 2 else {
    fatalError("Usage: swift make-icon.swift <out.iconset> [Surge MainIcon.icns]")
}
let output = URL(fileURLWithPath: arguments[1])
let source = URL(fileURLWithPath: arguments.count >= 3
    ? arguments[2]
    : "/Applications/Surge.app/Contents/Resources/MainIcon.icns")
guard FileManager.default.fileExists(atPath: source.path) else {
    fatalError("Surge icon not found at \(source.path). Pass the MainIcon.icns path explicitly.")
}

let extracted = FileManager.default.temporaryDirectory
    .appendingPathComponent("Sluice-icon-source-\(UUID().uuidString).iconset")
defer { try? FileManager.default.removeItem(at: extracted) }
let unpack = Process()
unpack.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
unpack.arguments = ["-c", "iconset", source.path, "-o", extracted.path]
try unpack.run()
unpack.waitUntilExit()
guard unpack.terminationStatus == 0 else { fatalError("Could not read Surge icon") }

try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
let renderer = CIContext(options: [.workingColorSpace: CGColorSpace(name: CGColorSpace.sRGB)!])
let space = CGColorSpaceCreateDeviceRGB()

func sourceName(for pixels: Int) -> String {
    switch pixels {
    case 16: "icon_16x16.png"
    case 32: "icon_16x16@2x.png"
    case 64, 128: "icon_128x128.png"
    default: "icon_128x128@2x.png"
    }
}

func recolouredImage(at pixels: Int) -> CGImage {
    let path = extracted.appendingPathComponent(sourceName(for: pixels))
    guard let input = CIImage(contentsOf: path) else { fatalError("Missing \(path.lastPathComponent)") }
    // The hue and saturation change only colour. Every edge, highlight, shadow,
    // translucent tile pixel and bar gap stays in the same place.
    let hue = CIFilter.hueAdjust()
    hue.inputImage = input
    hue.angle = -1.05
    let colour = CIFilter.colorControls()
    colour.inputImage = hue.outputImage
    colour.saturation = 0.82
    let image = renderer.createCGImage(colour.outputImage!, from: input.extent)!
    guard image.width != pixels else { return image }
    let context = CGContext(data: nil, width: pixels, height: pixels, bitsPerComponent: 8,
                            bytesPerRow: 0, space: space,
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    context.interpolationQuality = .high
    context.draw(image, in: CGRect(x: 0, y: 0, width: pixels, height: pixels))
    return context.makeImage()!
}

for pointSize in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = pointSize * scale
        let image = recolouredImage(at: pixels)
        let name = scale == 1 ? "icon_\(pointSize)x\(pointSize).png" : "icon_\(pointSize)x\(pointSize)@2x.png"
        let data = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])!
        try data.write(to: output.appendingPathComponent(name))
    }
}
