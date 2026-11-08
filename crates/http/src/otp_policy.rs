//! The realm OTP policy's rules shared by the admin API and TOTP setup:
//! which authenticator apps support it and what a new credential keeps.

use rs_keycloak_protocols::totp::CodeFormat;
use rs_keycloak_storage_postgres::{OtpData, OtpPolicy};

/// The apps whose `OTPApplicationProvider.supports` accepts the policy,
/// as message keys sorted as the representation lists them: FreeOTP
/// always, Google Authenticator for HOTP or 30-second TOTP, Microsoft
/// Authenticator for 6-digit HMAC-SHA1 30-second TOTP.
pub(crate) fn supported_applications(policy: &OtpPolicy) -> Vec<&'static str> {
    let totp = policy.kind == "totp";
    let mut apps = vec!["totpAppFreeOTPName"];
    if policy.kind == "hotp" || totp && policy.period == 30 {
        apps.push("totpAppGoogleName");
    }
    if totp
        && policy.digits == 6
        && policy.algorithm.as_deref() == Some("HmacSHA1")
        && policy.period == 30
    {
        apps.push("totpAppMicrosoftAuthenticatorName");
    }
    apps
}

/// What a credential made under the policy keeps, as
/// `OTPCredentialModel.createFromPolicy`.
pub(crate) fn credential_data(policy: &OtpPolicy) -> OtpData {
    OtpData {
        kind: Some(policy.kind.clone()),
        algorithm: policy.algorithm.clone(),
        digits: Some(policy.digits),
        period: Some(policy.period),
        counter: Some(i64::from(policy.initial_counter)),
    }
}

/// How a credential's codes are made, if its stored policy can make any.
pub(crate) fn code_format(data: &OtpData) -> Option<CodeFormat> {
    CodeFormat::new(data.algorithm.as_deref(), data.digits?)
}

/// The look-ahead window as a count; a negative one checks only the
/// expected code.
pub(crate) fn window(look_ahead: i32) -> u64 {
    u64::try_from(look_ahead).unwrap_or(0)
}
