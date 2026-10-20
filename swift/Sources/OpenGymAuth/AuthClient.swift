import CryptoKit
import Foundation
import Security
import AuthenticationServices

public struct AuthProfile: Decodable, Sendable {
    public let id: String
    public let name: String
    public let admin: Bool
    public let authMethods: [String]?
}

public struct ProviderChallenge: Decodable, Sendable {
    public let cid: String
    public let nonce: String
}

public struct AuthConfiguration: Decodable, Sendable {
    public let invite_only: Bool
    public let password_enabled: Bool
    public let google_enabled: Bool
    public let apple_enabled: Bool
    public let google_client_id: String?
    public let google_ios_client_id: String?
    public let apple_client_id: String?
    public let rp_id: String?
}

private struct AuthResponse: Decodable {
    let user: AuthProfile
    let sessionToken: String?
}

/// Shared OpenGym API client. API sessions are stored only in the iOS Keychain.
public actor OpenGymAuthClient {
    public static let shared = OpenGymAuthClient()
    private let baseURL = URL(string: "https://gym.adrenocromo.com")!
    private let keychain = KeychainSessionStore()

    public func configuration() async throws -> AuthConfiguration {
        try await get("/api/config")
    }

    public func currentUser() async throws -> AuthProfile {
        let response: UserEnvelope = try await get("/api/me", authenticated: true)
        return response.user
    }

    public func register(name: String, email: String, password: String, inviteCode: String = "") async throws -> AuthProfile {
        try await authenticate("/api/auth/password/register", body: [
            "name": name, "email": email, "password": password, "code": inviteCode, "client": "native"
        ])
    }

    public func login(email: String, password: String) async throws -> AuthProfile {
        try await authenticate("/api/auth/password/login", body: [
            "email": email, "password": password, "client": "native"
        ])
    }

    public func providerChallenge(_ provider: String) async throws -> ProviderChallenge {
        try await post("/api/auth/provider/challenge", body: ["provider": provider])
    }

    public func signIn(provider: String, challenge: ProviderChallenge, idToken: String, name: String = "", inviteCode: String = "") async throws -> AuthProfile {
        try await authenticate("/api/auth/provider/\(provider)", body: [
            "cid": challenge.cid, "idToken": idToken, "name": name, "code": inviteCode, "client": "native"
        ])
    }

    public func resetPassword(code: String, newPassword: String) async throws {
        let _: EmptyResponse = try await post("/api/auth/password/reset", body: ["code": code, "newPassword": newPassword])
    }

    public func link(provider: String, challenge: ProviderChallenge, idToken: String) async throws -> AuthProfile {
        let result: UserEnvelope = try await post("/api/auth/provider/link/\(provider)", body: [
            "cid": challenge.cid, "idToken": idToken
        ], authenticated: true)
        return result.user
    }

    public func linkPassword(email: String, password: String) async throws -> AuthProfile {
        let result: UserEnvelope = try await post("/api/auth/password/link", body: ["email": email, "password": password], authenticated: true)
        return result.user
    }

    public func changePassword(current: String, new: String) async throws -> AuthProfile {
        try await authenticate("/api/auth/password/change", body: [
            "password": current, "newPassword": new, "client": "native"
        ])
    }

    public func registerPasskey(name: String, inviteCode: String = "") async throws -> AuthProfile {
        let optionsResponse = try await postObject("/api/register/options", body: ["name": name, "code": inviteCode])
        guard let cid = optionsResponse["cid"] as? String,
              let options = optionsResponse["options"] as? [String: Any],
              let challengeString = options["challenge"] as? String,
              let user = options["user"] as? [String: Any],
              let userIDString = user["id"] as? String,
              let userName = user["name"] as? String else { throw AuthClientError.invalidResponse }
        let challenge = try Self.decodeBase64URL(challengeString)
        let userID = try Self.decodeBase64URL(userIDString)
        let request = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: try await relyingPartyID())
            .createCredentialRegistrationRequest(challenge: challenge, name: userName, userID: userID)
        let result = try await PasskeyAuthorization.perform(request)
        guard let credential = result as? ASAuthorizationPlatformPublicKeyCredentialRegistration else { throw AuthClientError.invalidResponse }
        let payload: [String: Any] = [
            "cid": cid,
            "client": "native",
            "credential": [
                "id": Self.encodeBase64URL(credential.credentialID),
                "rawId": Self.encodeBase64URL(credential.credentialID),
                "type": "public-key",
                "response": [
                    "attestationObject": Self.encodeBase64URL(credential.rawAttestationObject ?? Data()),
                    "clientDataJSON": Self.encodeBase64URL(credential.rawClientDataJSON),
                    "transports": ["internal"]
                ],
                "clientExtensionResults": [:] as [String: String],
                "authenticatorAttachment": "platform"
            ] as [String: Any]
        ]
        let response: AuthResponse = try await postJSON("/api/register/verify", body: payload)
        guard let token = response.sessionToken else { throw AuthClientError.invalidResponse }
        keychain.save(token)
        return response.user
    }

    public func signInWithPasskey() async throws -> AuthProfile {
        let optionsResponse = try await postObject("/api/login/options", body: [:])
        guard let cid = optionsResponse["cid"] as? String,
              let options = optionsResponse["options"] as? [String: Any],
              let challengeString = options["challenge"] as? String else { throw AuthClientError.invalidResponse }
        let challenge = try Self.decodeBase64URL(challengeString)
        let request = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: try await relyingPartyID())
            .createCredentialAssertionRequest(challenge: challenge)
        let result = try await PasskeyAuthorization.perform(request)
        guard let credential = result as? ASAuthorizationPlatformPublicKeyCredentialAssertion else { throw AuthClientError.invalidResponse }
        let payload: [String: Any] = [
            "cid": cid,
            "client": "native",
            "credential": [
                "id": Self.encodeBase64URL(credential.credentialID),
                "rawId": Self.encodeBase64URL(credential.credentialID),
                "type": "public-key",
                "response": [
                    "authenticatorData": Self.encodeBase64URL(credential.rawAuthenticatorData),
                    "clientDataJSON": Self.encodeBase64URL(credential.rawClientDataJSON),
                    "signature": Self.encodeBase64URL(credential.signature),
                    "userHandle": credential.userID.isEmpty ? (NSNull() as Any) : Self.encodeBase64URL(credential.userID)
                ],
                "clientExtensionResults": [:] as [String: String],
                "authenticatorAttachment": "platform"
            ] as [String: Any]
        ]
        let response: AuthResponse = try await postJSON("/api/login/verify", body: payload)
        guard let token = response.sessionToken else { throw AuthClientError.invalidResponse }
        keychain.save(token)
        return response.user
    }

    public func logout() async {
        let _: EmptyResponse? = try? await post("/api/logout", body: [:], authenticated: true)
        keychain.remove()
    }

    public static func appleNonceHash(_ nonce: String) -> String {
        SHA256.hash(data: Data(nonce.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private func authenticate(_ path: String, body: [String: String]) async throws -> AuthProfile {
        let response: AuthResponse = try await post(path, body: body)
        guard let token = response.sessionToken else { throw AuthClientError.invalidResponse }
        keychain.save(token)
        return response.user
    }

    private func get<T: Decodable>(_ path: String, authenticated: Bool = false) async throws -> T {
        try await request(path, method: "GET", body: nil, authenticated: authenticated)
    }

    private func post<T: Decodable>(_ path: String, body: [String: String], authenticated: Bool = false) async throws -> T {
        let encoded = try JSONSerialization.data(withJSONObject: body)
        return try await request(path, method: "POST", body: encoded, authenticated: authenticated)
    }

    private func postObject(_ path: String, body: [String: String]) async throws -> [String: Any] {
        let encoded = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await rawRequest(path, method: "POST", body: encoded, authenticated: false)
        guard (200..<300).contains(response.statusCode) else { throw serverError(data, status: response.statusCode) }
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw AuthClientError.invalidResponse }
        return object
    }

    private func postJSON<T: Decodable>(_ path: String, body: [String: Any]) async throws -> T {
        let encoded = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await rawRequest(path, method: "POST", body: encoded, authenticated: false)
        guard (200..<300).contains(response.statusCode) else { throw serverError(data, status: response.statusCode) }
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func request<T: Decodable>(_ path: String, method: String, body: Data?, authenticated: Bool) async throws -> T {
        let (data, http) = try await rawRequest(path, method: method, body: body, authenticated: authenticated)
        guard (200..<300).contains(http.statusCode) else { throw serverError(data, status: http.statusCode) }
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func rawRequest(_ path: String, method: String, body: Data?, authenticated: Bool) async throws -> (Data, HTTPURLResponse) {
        var request = URLRequest(url: baseURL.appending(path: path))
        request.httpMethod = method
        request.timeoutInterval = 20
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        if authenticated, let token = keychain.load() { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw AuthClientError.invalidResponse }
        return (data, http)
    }

    private func serverError(_ data: Data, status: Int) -> AuthClientError {
        let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        return .server(object?["error"] as? String ?? "HTTP \(status)")
    }

    private func relyingPartyID() async throws -> String {
        let config: AuthConfiguration = try await configuration()
        guard let rpID = config.rp_id, !rpID.isEmpty else { throw AuthClientError.invalidResponse }
        return rpID
    }

    private static func decodeBase64URL(_ value: String) throws -> Data {
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64) else { throw AuthClientError.invalidResponse }
        return data
    }

    private static func encodeBase64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}

private struct UserEnvelope: Decodable { let user: AuthProfile }
private struct EmptyResponse: Decodable { let ok: Bool? }

public enum AuthClientError: Error, LocalizedError {
    case invalidResponse
    case server(String)
    public var errorDescription: String? {
        switch self {
        case .invalidResponse: return "The server returned an invalid response."
        case .server(let message): return message
        }
    }
}

private struct KeychainSessionStore {
    private let service = "com.adrenocromo.gym.session"
    private let account = "bearer"

    func save(_ token: String) {
        remove()
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: Data(token.utf8)
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    func load() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func remove() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}
