// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "EcliptixOPAQUE",
    platforms: [
        .iOS(.v17),
        .macOS(.v11)
    ],
    products: [
        // Swift wrapper library
        .library(
            name: "EcliptixOPAQUE",
            targets: ["EcliptixOPAQUE"]
        )
    ],
    targets: [
        // Swift wrapper providing a Swift-native API
        .target(
            name: "EcliptixOPAQUE",
            dependencies: ["EcliptixOPAQUEBinary"],
            path: "Sources/EcliptixOPAQUE"
        ),

        // Binary target - XCFramework with all dependencies bundled
        // For local development, use path:
        .binaryTarget(
            name: "EcliptixOPAQUEBinary",
            path: "../dist/apple/EcliptixOPAQUE.xcframework"
        )

        // For release distribution via GitHub Releases, use:
        // .binaryTarget(
        //     name: "EcliptixOPAQUEBinary",
        //     url: "https://github.com/oleksandrmelnychenko/ecliptix-opaque/releases/download/v1.x.x/EcliptixOPAQUE.xcframework.zip",
        //     checksum: "<SHA256_CHECKSUM>"
        // )
    ]
)
