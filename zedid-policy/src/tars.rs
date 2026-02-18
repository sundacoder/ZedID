use crate::error::PolicyError;
use crate::models::PolicyKind;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Tetrate Agent Router Service (TARS) client
/// Refactored from Python OpenAI client to Rust
pub struct TarsClient {
    base_url: String,
    api_key: Option<String>,
    http: reqwest::Client,
    mode: TarsMode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TarsMode {
    Live,
    Simulation,
}

#[derive(Debug, Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<Message>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<Choice>,
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: Message,
}

#[derive(Debug, Deserialize)]
struct Usage {
    total_tokens: u32,
}

impl TarsClient {
    pub fn new(endpoint: &str, api_key: Option<String>) -> Self {
        // Determine mode based on endpoint or API key presence
        let mode = if api_key.is_some() && !endpoint.contains("simulation") {
            TarsMode::Live
        } else {
            TarsMode::Simulation
        };

        let base_url = endpoint.trim_end_matches('/').to_string();

        info!("TARS client initialized in {:?} mode. Endpoint: {}", mode, base_url);

        Self {
            base_url,
            api_key,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap(),
            mode,
        }
    }

    /// Route a policy generation request through TARS
    /// Matches client.chat.completions.create(...) from the Python SDK
    pub async fn generate_policy(
        &self,
        prompt: &str,
        kind: &PolicyKind,
    ) -> Result<(String, String, Option<u32>), PolicyError> {
        if self.mode == TarsMode::Simulation {
            return Ok(self.simulate_response(prompt, kind));
        }

        // TARS routing: Select model based on complexity/type
        let model = match kind {
            PolicyKind::Rego => "gpt-4o",
            PolicyKind::Cedar => "gpt-4o",
            _ => "gpt-4o-mini",
        };

        let request = ChatCompletionRequest {
            model: model.to_string(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: "You are ZedID, an expert in Zero Trust policy generation.".to_string(),
                },
                Message {
                    role: "user".to_string(),
                    content: prompt.to_string(),
                },
            ],
        };

        // Construct URL: base_url + /chat/completions (Standard OpenAI API path)
        // If base_url is "https://api.router.tetrate.ai/v1", we append "/chat/completions"
        let url = format!("{}/chat/completions", self.base_url);

        debug!("Sending request to TARS: {}", url);

        let mut req_builder = self.http.post(&url).json(&request);

        if let Some(key) = &self.api_key {
            req_builder = req_builder.bearer_auth(key);
        }

        let response = req_builder
            .send()
            .await
            .map_err(|e| PolicyError::TarsError(format!("Network error: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(PolicyError::TarsError(format!(
                "TARS API failed: {} - {}",
                status, text
            )));
        }

        let chat_resp: ChatCompletionResponse = response
            .json()
            .await
            .map_err(|e| PolicyError::TarsError(format!("Parse error: {}", e)))?;

        let content = chat_resp
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        let tokens = chat_resp.usage.map(|u| u.total_tokens);

        Ok((content, model.to_string(), tokens))
    }

    fn simulate_response(&self, prompt: &str, _kind: &PolicyKind) -> (String, String, Option<u32>) {
        // Simulation mode: generate a realistic Rego policy stub
        // In production, TARS routes to the optimal LLM (Gemini, GPT-4o, etc.)
        let content = format!(
            "# Simulated Rego Policy\n# Intent: {}\npackage zedid.generated\n\nimport future.keywords.if\n\ndefault allow := false\n\nallow if {{\n    input.trust_level >= 2\n}}\n",
            &prompt[..prompt.len().min(80)]
        );
        (content, "simulation-mode".to_string(), Some(42))
    }
}
