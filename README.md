# RustyNetCracker
Advanced credential-cracking tool in Rust, designed to perform brute-force and dictionary attacks on various network protocols with high efficiency and reliabilit

## Key Features

* Multi-Protocol Support: Support for SSH, FTP, HTTP, SMTP, and other common protocols.
* High Performance: Utilize Rust's concurrency model to perform high-speed attacks.
* Distributed Cracking: Capability to distribute the cracking process across multiple machines.
* Customization: Allow users to customize attack parameters, wordlists, and rules.
* Reporting: Generate detailed reports on successful attacks and attempts.

## Installation

1. Clone the repository:
```bash
git clone
```

2. Build the project:
```bash
cargo build --release
```

## Usage

```bash
cargo run -- --target <target_address> --protocol <protocol> --credentials <username:password> --log_file <log_file_path>

cargo run -- --target 192.168.1.100:22 --protocol ssh --credentials user:password123 --log_file custom_log.txt --log_level INFO

```