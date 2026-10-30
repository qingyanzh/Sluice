// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "SluiceApp",
    platforms: [.macOS(.v14)],
    targets: [
        .target(name: "SluiceHelperShared", path: "Sources/SluiceHelperShared"),
        .executableTarget(name: "SluiceApp", dependencies: ["SluiceHelperShared"], path: "Sources/SluiceApp"),
        // Privileged launchd daemon that runs the core as root for enhanced mode (docs/helper.md).
        .executableTarget(name: "SluiceHelper", dependencies: ["SluiceHelperShared"], path: "Sources/SluiceHelper"),
        .testTarget(name: "SluiceAppTests", dependencies: ["SluiceApp"]),
    ]
)
