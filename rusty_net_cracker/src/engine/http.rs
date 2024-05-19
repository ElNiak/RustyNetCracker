// src/engine/http.rs
use reqwest::blocking::Client;
use super::AttackModule;

pub struct HttpModule;

impl AttackModule for HttpModule {
    fn perform_attack(&self, target: &str, credentials: &str) -> Result<(), String> {
        let parts: Vec<&str> = credentials.split(':').collect();
        if parts.len() != 2 {
            return Err("Invalid credentials format. Use username:password".to_string());
        }
        let username = parts[0];
        let password = parts[1];

        let client = Client::new();
        let res = client.post(target)
            .form(&[("username", username), ("password", password)])
            .send()
            .map_err(|e| e.to_string())?;

        if res.status().is_success() {
            Ok(())
        } else {
            Err("Authentication failed".to_string())
        }
    }
}
