// src/engine/ftp.rs
use ftp::FtpStream;
use super::AttackModule;

pub struct FtpModule;

impl AttackModule for FtpModule {
    fn perform_attack(&self, target: &str, credentials: &str) -> Result<(), String> {
        let parts: Vec<&str> = credentials.split(':').collect();
        if parts.len() != 2 {
            return Err("Invalid credentials format. Use username:password".to_string());
        }
        let username = parts[0];
        let password = parts[1];

        let mut ftp_stream = FtpStream::connect(target).map_err(|e| e.to_string())?;
        ftp_stream.login(username, password).map_err(|e| e.to_string())?;
        
        Ok(())
    }
}
