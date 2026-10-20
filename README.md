# OpenGym Swift auth starter

This repository contains an iOS SwiftUI authentication starter for the OpenGym API at `https://gym.adrenocromo.com`. It supports email/password registration and login, native passkeys, Google Sign-In, Sign in with Apple, one-time admin-issued password reset codes, and Keychain-backed bearer sessions. It is an authentication slice; workout screens and data sync UI are not included yet.

## Use in an iOS app

Add `swift/` as a local Swift Package in Xcode, then show `OpenGymSignInView()` from the host app. The package targets iOS 16 and requires GoogleSignIn-iOS 9.0 or newer for server nonce protection. Set the host app's bundle identifier to `com.adrenocromo.gym` or update the registered provider identifiers to match.

For Google, add the iOS OAuth client ID to `GOOGLE_IOS_CLIENT_ID`, include it and the web/server client ID in `GOOGLE_CLIENT_IDS`, and configure the reversed client ID URL scheme required by GoogleSignIn in the host app's URL Types. The server client ID must also be `GOOGLE_WEB_CLIENT_ID`.

For Apple, enable Sign in with Apple for the host app's App ID. For web/Android Apple sign-in, also create a Services ID, register `https://gym.adrenocromo.com/api/auth/apple/callback` as a return URL, set it as `APPLE_WEB_CLIENT_ID` and `APPLE_REDIRECT_URL`, and include both Apple audiences in `APPLE_CLIENT_IDS`. This backend validates Apple ID tokens against Apple's published keys; it does not need an Apple private signing key or client secret.

Native passkeys use the API's configured `RP_ID`. Configure the iOS host app's Associated Domains capability with `webcredentials:gym.adrenocromo.com`, and serve a valid Apple App Site Association file for that RP ID that lists the host app's Team ID and bundle ID. For a different deployment domain, change the API `RP_ID` and use that domain in the entitlement and association file.

## Account behavior

Open sign-up is the default; set `INVITE_ONLY=1` on the server to require invite codes. Passwords are 12–128 characters. No email is sent and password emails remain unverified, so recovery uses a one-time reset code issued by an OpenGym administrator. Configure `ADMIN_UIDS` and the API provider IDs before expecting those server-side features to work.

The API stores Apple/Google identities by provider subject and does not silently merge accounts based on matching email addresses. Users can link credentials after signing in through the web app's Settings page.
