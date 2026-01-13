#[derive(Debug, Clone)]
pub(crate) enum StatusAccountDisplay {
    ChatGpt {
        email: Option<String>,
        plan: Option<String>,
    },
    ApiKey,
    AzureAad {
        email: Option<String>,
        tenant_id: String,
    },
}
