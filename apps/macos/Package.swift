// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "SluiceApp",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.6.4"),
    ],
    targets: [
        .executableTarget(
            name: "SluiceApp",
            dependencies: [.product(name: "Sparkle", package: "Sparkle")],
            path: "Sources/SluiceApp",
            // build-app.sh embeds Sparkle.framework in Contents/Frameworks.
            linkerSettings: [.unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"])]
        ),
        .testTarget(name: "SluiceAppTests", dependencies: ["SluiceApp"]),
    ]
)
