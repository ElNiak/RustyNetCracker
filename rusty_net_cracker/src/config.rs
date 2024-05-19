pub enum LogLevel {
    INFO,
    WARNING,
    ERROR,
}

pub struct Config {
    pub log_file: String,
    pub log_level: LogLevel,
}

impl Config {
    pub fn new(log_file: &str, log_level: LogLevel) -> Self {
        Config {
            log_file: log_file.to_string(),
            log_level,
        }
    }
}