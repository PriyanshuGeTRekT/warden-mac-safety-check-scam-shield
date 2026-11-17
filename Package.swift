// swift-tools-version: 6.0
import PackageDescription

let v5: [SwiftSetting] = [.swiftLanguageMode(.v5)]

let package = Package(
    name: "Warden",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "WardenCore", targets: ["WardenCore"]),
        .executable(name: "warden", targets: ["warden"]),
        .executable(name: "WardenBar", targets: ["WardenBar"]),
    ],
    targets: [
        .target(name: "WardenCore", swiftSettings: v5),
        .executableTarget(name: "warden", dependencies: ["WardenCore"], swiftSettings: v5),
        .executableTarget(name: "WardenBar", dependencies: ["WardenCore"], swiftSettings: v5),
        .testTarget(name: "WardenCoreTests", dependencies: ["WardenCore"], swiftSettings: v5),
    ]
)
