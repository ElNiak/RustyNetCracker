// src/engine/ssh.rs
use ssh2::Session;
use std::net::TcpStream;
use super::AttackModule;

pub struct SshModule;

impl AttackModule for SshModule {
    fn perform_attack(&self, target: &str, credentials: &str) -> Result<(), String> {
        let parts: Vec<&str> = credentials.split(':').collect();
        if parts.len() != 2 {
            return Err("Invalid credentials format. Use username:password".to_string());
        }
        let username = parts[0];
        let password = parts[1];

        let tcp = TcpStream::connect(target).map_err(|e| e.to_string())?;
        let mut session = Session::new().map_err(|e| e.to_string())?;
        session.set_tcp_stream(tcp);
        session.handshake().map_err(|e| e.to_string())?;

        session.userauth_password(username, password).map_err(|e| e.to_string())?;
        if session.authenticated() {
            Ok(())
        } else {
            Err("Authentication failed".to_string())
        }
    }
}
