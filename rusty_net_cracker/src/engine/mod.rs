// src/engine/mod.rs
pub mod ssh;
pub mod ftp;
pub mod http;

pub trait AttackModule {
    fn perform_attack(&self, target: &str, credentials: &str) -> Result<(), String>;
}
