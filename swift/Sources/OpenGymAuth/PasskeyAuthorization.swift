import AuthenticationServices
import UIKit

@MainActor
enum PasskeyAuthorization {
    static func perform(_ request: ASAuthorizationRequest) async throws -> ASAuthorizationCredential {
        guard let window = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
            .flatMap(\.windows)
            .first(where: \.isKeyWindow) else { throw AuthClientError.invalidResponse }
        let delegate = AuthorizationDelegate(window: window)
        return try await delegate.perform(request)
    }
}

@MainActor
private final class AuthorizationDelegate: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    private let window: UIWindow

    init(window: UIWindow) { self.window = window }

    func perform(_ request: ASAuthorizationRequest) async throws -> ASAuthorizationCredential {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let controller = ASAuthorizationController(authorizationRequests: [request])
            self.controller = controller
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }

    private var continuation: CheckedContinuation<ASAuthorizationCredential, Error>?
    private var controller: ASAuthorizationController?

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor { window }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        continuation?.resume(returning: authorization.credential)
        continuation = nil
        self.controller = nil
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        continuation?.resume(throwing: error)
        continuation = nil
        self.controller = nil
    }
}
