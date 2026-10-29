// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "SluiceApp",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(name: "SluiceApp", path: "Sources/SluiceApp"),
    ]
)
