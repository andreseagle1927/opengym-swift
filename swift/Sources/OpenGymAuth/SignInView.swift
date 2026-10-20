import AuthenticationServices
import GoogleSignIn
import GoogleSignInSwift
import SwiftUI
import UIKit

@MainActor
public final class OpenGymAuthModel: ObservableObject {
    @Published public private(set) var profile: AuthProfile?
    @Published public private(set) var configuration: AuthConfiguration?
    @Published public var message = ""
    @Published public var isBusy = false
    @Published public var resetMessage = ""
    public let client: OpenGymAuthClient

    public init(client: OpenGymAuthClient = .shared) { self.client = client }

    public func load() async {
        do { configuration = try await client.configuration() } catch { message = error.localizedDescription }
        if let user = try? await client.currentUser() { profile = user }
    }

    public func login(email: String, password: String) async { await run { try await client.login(email: email, password: password) } }
    public func register(name: String, email: String, password: String, inviteCode: String) async {
        await run { try await client.register(name: name, email: email, password: password, inviteCode: inviteCode) }
    }
    public func registerPasskey(name: String, inviteCode: String) async {
        await run { try await client.registerPasskey(name: name, inviteCode: inviteCode) }
    }
    public func signInWithPasskey() async { await run { try await client.signInWithPasskey() } }

    public func signIn(provider: String, challenge: ProviderChallenge, idToken: String, name: String = "", inviteCode: String = "") async {
        await run { try await client.signIn(provider: provider, challenge: challenge, idToken: idToken, name: name, inviteCode: inviteCode) }
    }

    public func resetPassword(code: String, newPassword: String) async {
        isBusy = true
        defer { isBusy = false }
        do { try await client.resetPassword(code: code, newPassword: newPassword); resetMessage = "Password reset. Sign in with your new password." }
        catch { resetMessage = error.localizedDescription }
    }

    public func signOut() async { await client.logout(); profile = nil }

    private func run(_ operation: () async throws -> AuthProfile) async {
        isBusy = true
        defer { isBusy = false }
        do { profile = try await operation(); message = "Signed in as \(profile?.name ?? "")" }
        catch { message = error.localizedDescription }
    }
}

@MainActor
public struct OpenGymSignInView: View {
    @StateObject private var model: OpenGymAuthModel
    @State private var isRegistering = false
    @State private var name = ""
    @State private var email = ""
    @State private var password = ""
    @State private var inviteCode = ""
    @State private var resetCode = ""
    @State private var resetPassword = ""
    @State private var appleChallenge: ProviderChallenge?

    public init(model: OpenGymAuthModel? = nil) { _model = StateObject(wrappedValue: model ?? OpenGymAuthModel()) }

    public var body: some View {
        VStack(spacing: 14) {
            Text("openGym").font(.largeTitle.bold())
            Text("Your training data, on your server.").foregroundStyle(.secondary)
            if let profile = model.profile {
                Text("Signed in as \(profile.name)")
                Button("Sign out") { Task { await model.signOut() } }
            } else {
                if isRegistering {
                    TextField("Name", text: $name).textContentType(.name)
                    if model.configuration?.invite_only == true {
                        TextField("Invite code", text: $inviteCode).textInputAutocapitalization(.characters)
                    }
                }
                TextField("Email", text: $email).textContentType(.emailAddress).keyboardType(.emailAddress).textInputAutocapitalization(.never)
                SecureField(isRegistering ? "Password (12 characters minimum)" : "Password", text: $password).textContentType(isRegistering ? .newPassword : .password)
                Button(isRegistering ? "Create account" : "Sign in with email") {
                    Task {
                        if isRegistering { await model.register(name: name, email: email, password: password, inviteCode: inviteCode) }
                        else { await model.login(email: email, password: password) }
                    }
                }.buttonStyle(.borderedProminent).disabled(model.isBusy || email.isEmpty || password.count < (isRegistering ? 12 : 1))

                Button(isRegistering ? "Create account with a passkey" : "Sign in with a passkey", systemImage: "key") {
                    Task {
                        if isRegistering { await model.registerPasskey(name: name, inviteCode: inviteCode) }
                        else { await model.signInWithPasskey() }
                    }
                }.buttonStyle(.bordered).disabled(model.isBusy || (isRegistering && name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty))

                if model.configuration?.google_enabled == true {
                    Button(action: { Task { await googleSignIn() } }) {
                        Label("Continue with Google", systemImage: "globe")
                    }.buttonStyle(.bordered).disabled(model.isBusy)
                }
                if model.configuration?.apple_enabled == true, let appleChallenge {
                    SignInWithAppleButton(.signIn, onRequest: { request in
                        request.requestedScopes = [.email, .fullName]
                        request.nonce = OpenGymAuthClient.appleNonceHash(appleChallenge.nonce)
                    }, onCompletion: { result in
                        Task { await completeApple(result, challenge: appleChallenge) }
                    })
                    .signInWithAppleButtonStyle(.black)
                    .frame(height: 48)
                    .disabled(model.isBusy)
                }
                Button(isRegistering ? "Already registered? Sign in" : "Create an account") { isRegistering.toggle() }
                    .buttonStyle(.plain)
                if !isRegistering {
                    DisclosureGroup("Have an administrator reset code?") {
                        TextField("One-time reset code", text: $resetCode).textInputAutocapitalization(.never)
                        SecureField("New password (12 characters minimum)", text: $resetPassword)
                        Button("Reset password") { Task { await model.resetPassword(code: resetCode, newPassword: resetPassword) } }
                            .disabled(model.isBusy || resetCode.isEmpty || resetPassword.count < 12)
                        if !model.resetMessage.isEmpty { Text(model.resetMessage).font(.footnote) }
                    }
                }
                if isRegistering {
                    Text("Email addresses are unverified. Password resets require an administrator.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            if !model.message.isEmpty { Text(model.message).font(.footnote).foregroundStyle(.secondary) }
        }
        .padding(24)
        .task {
            await model.load()
            await refreshAppleChallenge()
        }
    }

    private func refreshAppleChallenge() async {
        guard model.configuration?.apple_enabled == true else { return }
        appleChallenge = try? await model.client.providerChallenge("apple")
    }

    private func googleSignIn() async {
        guard let config = model.configuration,
              let iosClient = config.google_ios_client_id,
              let serverClient = config.google_client_id,
              let presenter = Self.presentingController() else { return }
        do {
            let challenge = try await model.client.providerChallenge("google")
            GIDSignIn.sharedInstance.configuration = GIDConfiguration(clientID: iosClient, serverClientID: serverClient)
            let result = try await GIDSignIn.sharedInstance.signIn(
                withPresenting: presenter,
                hint: nil,
                additionalScopes: [],
                nonce: challenge.nonce
            )
            guard let token = result.user.idToken?.tokenString else {
                model.message = "Google did not return an identity token."
                return
            }
            await model.signIn(provider: "google", challenge: challenge, idToken: token, name: result.user.profile?.name ?? "", inviteCode: inviteCode)
        } catch { model.message = error.localizedDescription }
    }

    private func completeApple(_ result: Result<ASAuthorization, Error>, challenge: ProviderChallenge) async {
        do {
            let authorization = try result.get()
            guard let credential = authorization.credential as? ASAuthorizationAppleIDCredential,
                  let tokenData = credential.identityToken,
                  let token = String(data: tokenData, encoding: .utf8) else {
                throw AuthClientError.invalidResponse
            }
            let fullName = [credential.fullName?.givenName, credential.fullName?.familyName].compactMap { $0 }.joined(separator: " ")
            await model.signIn(provider: "apple", challenge: challenge, idToken: token, name: fullName, inviteCode: inviteCode)
            await refreshAppleChallenge()
        } catch { model.message = error.localizedDescription; await refreshAppleChallenge() }
    }

    private static func presentingController() -> UIViewController? {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first(where: \.isKeyWindow)?.rootViewController
    }
}
