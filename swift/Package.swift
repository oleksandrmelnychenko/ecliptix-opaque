// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "EcliptixOPAQUE",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "EcliptixOPAQUE",
            targets: ["EcliptixOPAQUE"]
        )
    ],
    targets: [
        .target(
            name: "EcliptixOPAQUE",
            dependencies: ["EcliptixOPAQUEBinary"],
            path: "Sources/EcliptixOPAQUE"
        ),

        // Binary target — XCFramework built from Rust via cargo-lipo / cargo-xcode
        // For local development:
        .binaryTarget(
            name: "EcliptixOPAQUEBinary",
            path: "../dist/apple/EcliptixOPAQUE.xcframework"
        )

        // For release distribution via GitHub Releases:
        // .binaryTarget(
        //     name: "EcliptixOPAQUEBinary",
        //     url: "https://github.com/oleksandrmelnychenko/ecliptix-opaque/releases/download/vX.Y.Z/EcliptixOPAQUE.xcframework.zip",
        //     checksum: "<SHA256_CHECKSUM>"
        // )
    ]
)
