//! Azure Active Directory (AAD) token data structures for Azure AI Foundry authentication.

use base64::Engine;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

/// Token data for Azure AAD authentication.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Default)]
pub struct AadTokenData {
    /// The access token for Azure API calls.
    pub access_token: String,

    /// The refresh token for obtaining new access tokens.
    pub refresh_token: Option<String>,

    /// Token expiration time as Unix timestamp.
    pub expires_on: Option<i64>,

    /// The Azure tenant ID.
    pub tenant_id: String,

    /// The Azure client ID used for authentication.
    pub client_id: String,

    /// The resource URL (scope) for the token.
    pub resource_url: String,

    /// Parsed information from the access token JWT.
    #[serde(default)]
    pub token_info: AadTokenInfo,
}

/// Parsed claims from an Azure AD access token.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AadTokenInfo {
    /// User's email or UPN (User Principal Name).
    pub email: Option<String>,

    /// Azure tenant ID from the token.
    pub tid: Option<String>,

    /// Object ID of the user.
    pub oid: Option<String>,

    /// Application ID.
    pub appid: Option<String>,

    /// Token audience (resource).
    pub aud: Option<String>,

    /// Token issued at timestamp.
    pub iat: Option<i64>,

    /// Token expiration timestamp.
    pub exp: Option<i64>,

    /// The raw JWT string.
    pub raw_jwt: String,
}

#[derive(Debug, Error)]
pub enum AadTokenInfoError {
    #[error("invalid token format")]
    InvalidFormat,
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// JWT claims structure for Azure AD tokens.
#[derive(Deserialize)]
struct AadClaims {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    upn: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    tid: Option<String>,
    #[serde(default)]
    oid: Option<String>,
    #[serde(default)]
    appid: Option<String>,
    #[serde(default)]
    aud: Option<String>,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    exp: Option<i64>,
}

/// Parse an Azure AD access token JWT to extract useful claims.
pub fn parse_aad_token(access_token: &str) -> Result<AadTokenInfo, AadTokenInfoError> {
    // JWT format: header.payload.signature
    let mut parts = access_token.split('.');
    let (_header_b64, payload_b64, _sig_b64) = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) if !h.is_empty() && !p.is_empty() && !s.is_empty() => {
            (h, p, s)
        }
        _ => return Err(AadTokenInfoError::InvalidFormat),
    };

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64)?;
    let claims: AadClaims = serde_json::from_slice(&payload_bytes)?;

    // Azure AD tokens may have email in different fields
    let email = claims
        .email
        .or(claims.upn)
        .or(claims.preferred_username);

    Ok(AadTokenInfo {
        email,
        tid: claims.tid,
        oid: claims.oid,
        appid: claims.appid,
        aud: claims.aud,
        iat: claims.iat,
        exp: claims.exp,
        raw_jwt: access_token.to_string(),
    })
}

impl AadTokenData {
    /// Check if the access token is expired (with a 5-minute buffer).
    pub fn is_expired(&self) -> bool {
        if let Some(expires_on) = self.expires_on {
            let now = chrono::Utc::now().timestamp();
            // Consider expired if within 5 minutes of expiration
            expires_on <= now + 300
        } else if let Some(exp) = self.token_info.exp {
            let now = chrono::Utc::now().timestamp();
            exp <= now + 300
        } else {
            // If we don't know when it expires, assume it's valid
            false
        }
    }

    /// Check if the token can be refreshed.
    pub fn can_refresh(&self) -> bool {
        self.refresh_token.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde::Serialize;

    #[test]
    fn parse_aad_token_extracts_claims() {
        #[derive(Serialize)]
        struct Header {
            alg: &'static str,
            typ: &'static str,
        }
        let header = Header {
            alg: "RS256",
            typ: "JWT",
        };

        let payload = serde_json::json!({
            "email": "user@example.com",
            "tid": "tenant-123",
            "oid": "object-456",
            "appid": "app-789",
            "aud": "https://cognitiveservices.azure.com",
            "iat": 1704067200,
            "exp": 1704070800
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"signature");
        let fake_jwt = format!("{header_b64}.{payload_b64}.{sig_b64}");

        let info = parse_aad_token(&fake_jwt).expect("should parse");
        assert_eq!(info.email.as_deref(), Some("user@example.com"));
        assert_eq!(info.tid.as_deref(), Some("tenant-123"));
        assert_eq!(info.oid.as_deref(), Some("object-456"));
        assert_eq!(info.exp, Some(1704070800));
    }

    #[test]
    fn parse_aad_token_uses_upn_when_email_missing() {
        #[derive(Serialize)]
        struct Header {
            alg: &'static str,
            typ: &'static str,
        }
        let header = Header {
            alg: "RS256",
            typ: "JWT",
        };

        let payload = serde_json::json!({
            "upn": "user@contoso.com",
            "tid": "tenant-123"
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"signature");
        let fake_jwt = format!("{header_b64}.{payload_b64}.{sig_b64}");

        let info = parse_aad_token(&fake_jwt).expect("should parse");
        assert_eq!(info.email.as_deref(), Some("user@contoso.com"));
    }

    #[test]
    fn aad_token_data_is_expired_checks_correctly() {
        let now = chrono::Utc::now().timestamp();

        // Token expired 10 minutes ago
        let expired_token = AadTokenData {
            access_token: String::new(),
            refresh_token: None,
            expires_on: Some(now - 600),
            tenant_id: String::new(),
            client_id: String::new(),
            resource_url: String::new(),
            token_info: AadTokenInfo::default(),
        };
        assert!(expired_token.is_expired());

        // Token expires in 1 hour
        let valid_token = AadTokenData {
            access_token: String::new(),
            refresh_token: None,
            expires_on: Some(now + 3600),
            tenant_id: String::new(),
            client_id: String::new(),
            resource_url: String::new(),
            token_info: AadTokenInfo::default(),
        };
        assert!(!valid_token.is_expired());

        // Token expires in 3 minutes (within buffer)
        let almost_expired = AadTokenData {
            access_token: String::new(),
            refresh_token: None,
            expires_on: Some(now + 180),
            tenant_id: String::new(),
            client_id: String::new(),
            resource_url: String::new(),
            token_info: AadTokenInfo::default(),
        };
        assert!(almost_expired.is_expired());
    }
}
