//! Azure Active Directory device code authentication flow for Azure AI Foundry.
//!
//! This module implements the OAuth 2.0 device authorization grant flow for Azure AD,
//! allowing CLI-based authentication to Azure AI Foundry resources.

use codex_core::aad_token_data::{parse_aad_token, AadTokenData};
use serde::Deserialize;
use serde::Serialize;
use std::io;
use std::time::Duration;
use std::time::Instant;

const ANSI_BLUE: &str = "\x1b[94m";
const ANSI_GRAY: &str = "\x1b[90m";
const ANSI_RESET: &str = "\x1b[0m";

/// Azure AD device code flow configuration.
#[derive(Debug, Clone)]
pub struct AadDeviceCodeConfig {
    /// Azure tenant ID (e.g., "common", "organizations", or a specific tenant GUID)
    pub tenant_id: String,
    /// Azure application (client) ID
    pub client_id: String,
    /// The scope/resource URL for the token (e.g., "https://cognitiveservices.azure.com/.default")
    pub scope: String,
}

impl AadDeviceCodeConfig {
    /// Create config for Azure AI Foundry / Cognitive Services.
    pub fn for_ai_foundry(tenant_id: String, client_id: String) -> Self {
        Self {
            tenant_id,
            client_id,
            scope: "https://cognitiveservices.azure.com/.default offline_access".to_string(),
        }
    }

    /// Get the Azure AD device authorization endpoint URL.
    pub fn device_authorization_url(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/devicecode",
            self.tenant_id
        )
    }

    /// Get the Azure AD token endpoint URL.
    pub fn token_url(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        )
    }
}

/// Response from the Azure AD device authorization endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct AadDeviceCodeResponse {
    /// The device code to poll with.
    pub device_code: String,
    /// The user code to display.
    pub user_code: String,
    /// URL the user should visit.
    pub verification_uri: String,
    /// Lifetime in seconds of the device code.
    pub expires_in: u64,
    /// Polling interval in seconds.
    pub interval: u64,
    /// Message to display to the user.
    pub message: String,
}

/// Azure AD device code for ongoing authentication.
#[derive(Debug, Clone)]
pub struct AadDeviceCode {
    pub verification_url: String,
    pub user_code: String,
    pub message: String,
    pub expires_in: u64,
    pub interval: u64,
    device_code: String,
    config: AadDeviceCodeConfig,
}

#[derive(Serialize)]
struct DeviceCodeRequest {
    client_id: String,
    scope: String,
}

#[derive(Serialize)]
struct TokenPollRequest {
    client_id: String,
    grant_type: String,
    device_code: String,
}

#[derive(Deserialize)]
struct TokenSuccessResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    #[allow(dead_code)]
    token_type: String,
    #[allow(dead_code)]
    scope: Option<String>,
}

#[derive(Deserialize)]
struct TokenErrorResponse {
    error: String,
    error_description: Option<String>,
}

/// Request a device code from Azure AD.
pub async fn request_aad_device_code(
    config: AadDeviceCodeConfig,
) -> io::Result<AadDeviceCode> {
    let client = reqwest::Client::new();
    let url = config.device_authorization_url();

    let request = DeviceCodeRequest {
        client_id: config.client_id.clone(),
        scope: config.scope.clone(),
    };

    let resp = client
        .post(&url)
        .form(&request)
        .send()
        .await
        .map_err(io::Error::other)?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(io::Error::other(format!(
            "Azure AD device code request failed with status {status}: {body}"
        )));
    }

    let device_resp: AadDeviceCodeResponse = resp.json().await.map_err(io::Error::other)?;

    Ok(AadDeviceCode {
        verification_url: device_resp.verification_uri,
        user_code: device_resp.user_code,
        message: device_resp.message,
        expires_in: device_resp.expires_in,
        interval: device_resp.interval,
        device_code: device_resp.device_code,
        config,
    })
}

/// Poll Azure AD for token completion.
pub async fn complete_aad_device_code_login(
    device_code: AadDeviceCode,
) -> io::Result<AadTokenData> {
    let client = reqwest::Client::new();
    let url = device_code.config.token_url();
    let max_wait = Duration::from_secs(device_code.expires_in);
    let poll_interval = Duration::from_secs(device_code.interval.max(5)); // Minimum 5 seconds
    let start = Instant::now();

    loop {
        let request = TokenPollRequest {
            client_id: device_code.config.client_id.clone(),
            grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            device_code: device_code.device_code.clone(),
        };

        let resp = client
            .post(&url)
            .form(&request)
            .send()
            .await
            .map_err(io::Error::other)?;

        let status = resp.status();
        let body = resp.text().await.map_err(io::Error::other)?;

        if status.is_success() {
            let token_resp: TokenSuccessResponse =
                serde_json::from_str(&body).map_err(io::Error::other)?;

            // Parse the access token to extract claims
            let token_info = parse_aad_token(&token_resp.access_token)
                .map_err(|e| io::Error::other(format!("Failed to parse AAD token: {e}")))?;

            let now = chrono::Utc::now().timestamp();
            let expires_on = token_resp.expires_in.map(|e| now + e as i64);

            return Ok(AadTokenData {
                access_token: token_resp.access_token,
                refresh_token: token_resp.refresh_token,
                expires_on,
                tenant_id: device_code.config.tenant_id.clone(),
                client_id: device_code.config.client_id.clone(),
                resource_url: device_code.config.scope.clone(),
                token_info,
            });
        }

        // Parse error response
        if let Ok(error_resp) = serde_json::from_str::<TokenErrorResponse>(&body) {
            match error_resp.error.as_str() {
                "authorization_pending" => {
                    // User hasn't authenticated yet, keep polling
                }
                "slow_down" => {
                    // We're polling too fast, increase interval
                    tokio::time::sleep(poll_interval * 2).await;
                    continue;
                }
                "expired_token" => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Device code has expired. Please try again.",
                    ));
                }
                "access_denied" => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        error_resp
                            .error_description
                            .unwrap_or_else(|| "Access denied by user.".to_string()),
                    ));
                }
                _ => {
                    return Err(io::Error::other(format!(
                        "Azure AD authentication failed: {} - {}",
                        error_resp.error,
                        error_resp.error_description.unwrap_or_default()
                    )));
                }
            }
        }

        // Check timeout
        if start.elapsed() >= max_wait {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Azure AD device authentication timed out.",
            ));
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Print the device code prompt to the user.
pub fn print_aad_device_code_prompt(device_code: &AadDeviceCode) {
    let version = env!("CARGO_PKG_VERSION");
    println!(
        "\nWelcome to Codex [v{ANSI_GRAY}{version}{ANSI_RESET}]\n{ANSI_GRAY}OpenAI's command-line coding agent{ANSI_RESET}\n\
\nFollow these steps to sign in with Azure Active Directory:\n\
\n1. Open this link in your browser and sign in to your Azure account\n   {ANSI_BLUE}{}{ANSI_RESET}\n\
\n2. Enter this code {ANSI_GRAY}(expires in {} seconds){ANSI_RESET}\n   {ANSI_BLUE}{}{ANSI_RESET}\n\
\n{ANSI_GRAY}Device codes are a common phishing target. Never share this code.{ANSI_RESET}\n",
        device_code.verification_url,
        device_code.expires_in,
        device_code.user_code,
    );
}

/// Full Azure AD device code login flow.
pub async fn run_aad_device_code_login(
    config: AadDeviceCodeConfig,
) -> io::Result<AadTokenData> {
    let device_code = request_aad_device_code(config).await?;
    print_aad_device_code_prompt(&device_code);
    complete_aad_device_code_login(device_code).await
}

/// Refresh an Azure AD token using a refresh token.
pub async fn refresh_aad_token(
    token_data: &AadTokenData,
) -> io::Result<AadTokenData> {
    let refresh_token = token_data
        .refresh_token
        .as_ref()
        .ok_or_else(|| io::Error::other("No refresh token available"))?;

    let client = reqwest::Client::new();
    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        token_data.tenant_id
    );

    let params = [
        ("client_id", token_data.client_id.as_str()),
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.as_str()),
        ("scope", token_data.resource_url.as_str()),
    ];

    let resp = client
        .post(&url)
        .form(&params)
        .send()
        .await
        .map_err(io::Error::other)?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(io::Error::other(format!(
            "Azure AD token refresh failed with status {status}: {body}"
        )));
    }

    let token_resp: TokenSuccessResponse = resp.json().await.map_err(io::Error::other)?;

    let token_info = parse_aad_token(&token_resp.access_token)
        .map_err(|e| io::Error::other(format!("Failed to parse refreshed AAD token: {e}")))?;

    let now = chrono::Utc::now().timestamp();
    let expires_on = token_resp.expires_in.map(|e| now + e as i64);

    Ok(AadTokenData {
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token.or(token_data.refresh_token.clone()),
        expires_on,
        tenant_id: token_data.tenant_id.clone(),
        client_id: token_data.client_id.clone(),
        resource_url: token_data.resource_url.clone(),
        token_info,
    })
}
