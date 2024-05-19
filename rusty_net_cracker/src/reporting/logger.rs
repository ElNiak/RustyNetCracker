use std::fs::OpenOptions;
use std::io::Write;
use chrono::Local;
use crate::config::{Config, LogLevel};

fn should_log(config: &Config, level: LogLevel) -> bool {
    match config.log_level {
        LogLevel::INFO => true,
        LogLevel::WARNING => matches!(level, LogLevel::WARNING | LogLevel::ERROR),
        LogLevel::ERROR => matches!(level, LogLevel::ERROR),
    }
}

pub fn log_start(config: &Config, target: &str, protocol: &str) {
    if should_log(config, LogLevel::INFO) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let message = format!("{} - INFO - Starting attack on {} using {}\n", timestamp, target, protocol);
        log(&config.log_file, message);
    }
}

pub fn log_string(config: &Config, message: &str) {
    if should_log(config, LogLevel::INFO) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let log_message = format!("{} - INFO - {}\n", timestamp, message);
        log(&config.log_file, log_message);
    }
}

pub fn log_attempt(config: &Config, target: &str, credentials: &str, success: bool) {
    if should_log(config, LogLevel::INFO) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let status = if success { "SUCCESS" } else { "FAILURE" };
        let message = format!("{} - INFO - Attempted {} on {} - {}\n", timestamp, credentials, target, status);
        log(&config.log_file, message);
    }
}

pub fn log_result(config: &Config, target: &str, protocol: &str, success: bool) {
    if should_log(config, LogLevel::INFO) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let status = if success { "SUCCESS" } else { "FAILURE" };
        let message = format!("{} - INFO - Attack on {} using {} - {}\n", timestamp, target, protocol, status);
        log(&config.log_file, message);
    }
}

pub fn log_error(config: &Config, message: &str) {
    if should_log(config, LogLevel::ERROR) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let log_message = format!("{} - ERROR - {}\n", timestamp, message);
        log(&config.log_file, log_message);
    }
}

fn log(log_file: &str, message: String) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
        .unwrap();
    file.write_all(message.as_bytes()).unwrap();
}
