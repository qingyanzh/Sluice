// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "SluiceApp",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.6.4"),
    ],
    targets: [
        .target(name: "SluiceHelperShared", path: "Sources/SluiceHelperShared"),
        .target(name: "SluiceCoreHash", path: "Sources/SluiceCoreHash"),
        .executableTarget(
            name: "SluiceApp",
            dependencies: ["SluiceHelperShared", .product(name: "Sparkle", package: "Sparkle")],
            path: "Sources/SluiceApp",
            // build-app.sh embeds Sparkle.framework in Contents/Frameworks.
            linkerSettings: [.unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"])]
        ),
        // Privileged launchd daemon that runs the core as root for enhanced mode (docs/helper.md).
        .executableTarget(name: "SluiceHelper", dependencies: ["SluiceHelperShared", "SluiceCoreHash"], path: "Sources/SluiceHelper"),
        .testTarget(name: "SluiceHelperTests", dependencies: ["SluiceHelper"]),
        .testTarget(name: "SluiceAppTests", dependencies: ["SluiceApp"], resources: [.copy("Fixtures")]),
    ]
)
