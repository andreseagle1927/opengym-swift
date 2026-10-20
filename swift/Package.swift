// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OpenGymAuth",
    platforms: [.iOS(.v16)],
    products: [.library(name: "OpenGymAuth", targets: ["OpenGymAuth"])],
    dependencies: [
        .package(url: "https://github.com/google/GoogleSignIn-iOS", from: "9.0.0")
    ],
    targets: [
        .target(name: "OpenGymAuth", dependencies: [
            .product(name: "GoogleSignIn", package: "GoogleSignIn-iOS"),
            .product(name: "GoogleSignInSwift", package: "GoogleSignIn-iOS")
        ])
    ]
)
