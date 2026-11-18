// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "SigSieveKit",
    platforms: [.macOS(.v13)],
    products: [.library(name: "SigSieveKit", targets: ["SigSieveKit"])],
    targets: [
        .target(name: "SigSieveKit"),
        .testTarget(name: "SigSieveKitTests", dependencies: ["SigSieveKit"]),
    ]
)
