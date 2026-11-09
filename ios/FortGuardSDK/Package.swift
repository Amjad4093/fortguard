// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "FortGuardSDK",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "FortGuardSDK", targets: ["FortGuardSDK"]),
    ],
    targets: [
        .target(name: "FortGuardSDK", path: "Sources/FortGuardSDK", resources: [.copy("PrivacyInfo.xcprivacy")]),
        .testTarget(name: "FortGuardSDKTests", dependencies: ["FortGuardSDK"], path: "Tests/FortGuardSDKTests"),
    ]
)
