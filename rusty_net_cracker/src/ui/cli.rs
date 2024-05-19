use clap::{App, Arg};
use crate::config::{Config, LogLevel};
use crate::engine::{AttackModule, ssh::SshModule, ftp::FtpModule, http::HttpModule};
use crate::reporting::logger::{log_start, log_string, log_attempt, log_result, log_error};
use crate::reporting::report::{generate_report, Report};

use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use itertools::Itertools;

fn parse_log_level(level: &str) -> LogLevel {
    match level {
        "INFO" => LogLevel::INFO,
        "WARNING" => LogLevel::WARNING,
        "ERROR" => LogLevel::ERROR,
        _ => LogLevel::INFO, // Default to INFO if an unknown level is provided
    }
}


pub fn run() {
    let matches = App::new("Rusty Net Cracker")
        .version("1.0")
        .author("Your Name <your.email@example.com>")
        .about("A high-performance, multi-protocol credential-cracking tool")
        .arg(Arg::with_name("target")
            .short('t')
            .long("target")
            .value_name("TARGET")
            .help("Sets the target to attack")
            .takes_value(true))
        .arg(Arg::with_name("protocol")
            .short('p')
            .long("protocol")
            .value_name("PROTOCOL")
            .help("Sets the protocol to use (ssh, ftp, http)")
            .takes_value(true))
        .arg(Arg::with_name("credentials")
            .short('c')
            .long("credentials")
            .value_name("CREDENTIALS")
            .help("Sets the credentials to use")
            .takes_value(true))
        .arg(Arg::with_name("credentials_file")
            .short('f')
            .long("credentials_file")
            .value_name("CREDENTIALS_FILE")
            .help("Sets the file containing credentials (one per line in username:password format)")
            .takes_value(true))
        .arg(Arg::with_name("username_wordlist")
            .short('u')
            .long("username_wordlist")
            .value_name("USERNAME_WORDLIST")
            .help("Sets the file containing usernames for brute force")
            .takes_value(true))
        .arg(Arg::with_name("password_wordlist")
            .short('w')
            .long("password_wordlist")
            .value_name("PASSWORD_WORDLIST")
            .help("Sets the file containing passwords for brute force")
            .takes_value(true))
        .arg(Arg::with_name("brute_force")
            .short('b')
            .long("brute_force")
            .help("Enable pure brute-force mode"))
        .arg(Arg::with_name("min_length")
            .long("min_length")
            .value_name("MIN_LENGTH")
            .help("Minimum length for brute force")
            .takes_value(true))
        .arg(Arg::with_name("max_length")
            .long("max_length")
            .value_name("MAX_LENGTH")
            .help("Maximum length for brute force")
            .takes_value(true))
        .arg(Arg::with_name("charset")
            .long("charset")
            .value_name("CHARSET")
            .help("Character set for brute force")
            .takes_value(true))
        .arg(Arg::with_name("cupp")
            .long("cupp")
            .help("Enable CUPP mode for generating personalized wordlists"))
        .arg(Arg::with_name("log_file")
            .short('l')
            .long("log_file")
            .value_name("LOG_FILE")
            .help("Sets the log file path")
            .takes_value(true))
        .arg(Arg::with_name("log_level")
            .short('v')
            .long("log_level")
            .value_name("LOG_LEVEL")
            .help("Sets the log level (INFO, WARNING, ERROR)")
            .takes_value(true))
    .get_matches();

    let target = matches.value_of("target").unwrap();
    let protocol = matches.value_of("protocol").unwrap();
    let log_file = matches.value_of("log_file").unwrap_or("log.txt");
    let log_level_str = matches.value_of("log_level").unwrap_or("INFO");
    let log_level = parse_log_level(log_level_str);

    let config = Config::new(log_file, log_level);

    log_start(&config, target, protocol);

    let attack_mode = if matches.is_present("brute_force") {
        "brute_force"
    } else if matches.is_present("cupp") {
        "cupp"
    } else if matches.is_present("credentials") {
        "credentials"
    } else if matches.is_present("credentials_file") {
        "credentials_file"
    } else if matches.is_present("username_wordlist") && matches.is_present("password_wordlist") {
        "username_wordlist and password_wordlist"
    } else {
        "unknown"
    };

    let mut log_message = format!("
    Starting attack with the following options: \n \
        Target: {}\n \
        Protocol: {}\n \
        Attack mode: {}\n \
        Log file: {}\n \
        Log level: {}\n", target, protocol, attack_mode,log_file, log_level_str);

    log_string(&config, &log_message);

    if matches.is_present("brute_force") {
        let min_length = matches.value_of("min_length").unwrap_or("1").parse::<usize>().unwrap();
        let max_length = matches.value_of("max_length").unwrap_or("4").parse::<usize>().unwrap();
        let charset = matches.value_of("charset").unwrap_or("abcdefghijklmnopqrstuvwxyz").chars().collect::<Vec<_>>();
        brute_force_attack(&config, target, protocol, &charset, min_length, max_length);
    } else if matches.is_present("cupp") {
        let wordlist = generate_cupp_wordlist();
        for credentials in wordlist {
            perform_attack(&config, target, protocol, &credentials);
        }
    } else if let Some(credentials_file) = matches.value_of("credentials_file") {
        if let Ok(lines) = read_lines(credentials_file) {
            for line in lines {
                if let Ok(credentials) = line {
                    perform_attack(&config, target, protocol, &credentials);
                }
            }
        }
    } else if let Some(credentials) = matches.value_of("credentials") {
        perform_attack(&config, target, protocol, credentials);
    } else if let (Some(username_wordlist), Some(password_wordlist)) = (matches.value_of("username_wordlist"), matches.value_of("password_wordlist")) {
        if let Ok(usernames) = read_lines(username_wordlist) {
            for username in usernames.flatten() {
                if let Ok(passwords) = read_lines(password_wordlist) {
                    for password in passwords.flatten() {
                        let credentials = format!("{}:{}", username, password);
                        perform_attack(&config, target, protocol, &credentials);
                    }
                }
            }
        }
    } else {
        println!("Either --credentials, --credentials_file, --username_wordlist and --password_wordlist, --brute_force, or --cupp must be provided.");
    }
}
    

fn perform_attack(config: &Config, target: &str, protocol: &str, credentials: &str) {
    let result = match protocol {
        "ssh" => SshModule.perform_attack(target, credentials),
        "ftp" => FtpModule.perform_attack(target, credentials),
        "http" => HttpModule.perform_attack(target, credentials),
        _ => Err("Unsupported protocol".to_string()),
    };

    match result {
        Ok(_) => {
            println!("Attack successful!");
            log_attempt(config, target, credentials, true);
            generate_report(&Report {
                target: target.to_string(),
                credentials: credentials.to_string(),
                success: true,
            });
            log_result(config, target, protocol, true);
        },
        Err(err) => {
            println!("Attack failed: {}", err);
            log_attempt(config, target, credentials, false);
            log_error(config, &err);
            log_result(config, target, protocol, false);
        },
    }
}

// Function to generate all possible combinations of the given character set
fn brute_force_attack(config: &Config, target: &str, protocol: &str, charset: &[char], min_length: usize, max_length: usize) {
    for length in min_length..=max_length {
        for combination in charset.iter().combinations(length) {
            let username: String = combination.iter().copied().collect();
            for combination in charset.iter().combinations(length) {
                let password: String = combination.iter().copied().collect();
                let credentials = format!("{}:{}", username, password);
                log_attempt(config, target, &credentials, false);
                perform_attack(config, target, protocol, &credentials);
            }
        }
    }
}

// Helper function to read lines from a file
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

// Integrate CUPP to generate personalized wordlists
fn generate_cupp_wordlist() -> Vec<String> {
    // Call the CUPP library or functions to generate wordlist
    // Here we mock the function for simplicity
    vec![
        "username1:password1".to_string(),
        "username2:password2".to_string(),
        "username3:password3".to_string(),
    ]
}