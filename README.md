# NetSleuth

NetSleuth is a comprehensive network scanning tool created with Rust's powerful asynchronous programming features. It is tailored to assist network administrators, cybersecurity enthusiasts, and IT professionals in discovering live hosts, open ports, and network services within specified IP ranges. By providing a swift and detailed overview of network topologies, NetSleuth facilitates vulnerability assessments and routine network management tasks. (currently in development more functions will be implemented soon)

## Features

- **IP Range Scanning:** Define IP ranges using CIDR notation or specific IP addresses for targeted scanning.
- **Port Scanning:** Identify open ports on single or multiple hosts.
- **Service Detection:** Discover common network services running on open ports.
- **Asynchronous Scanning:** Utilize Rust's Tokio runtime for fast, concurrent network scans.
- **Interactive CLI:** Easy to use command-line interface for configuring and executing scans.

## Installation

Make sure you have Rust installed on your machine. If not, download and install Rust from the [official website](https://rust-lang.org).

Clone the NetSleuth repository to your local machine:

```bash
git clone https://github.com/yourusername/NetSleuth.git
cd NetSleuth
```

Build the project using Cargo:

```bash
cargo build --release
```

The built binary will be located in the `target/release` directory.

## Usage

Run NetSleuth from the command line and follow the interactive prompts to configure your network scan:

```bash
./target/release/netsleuth
```

You can also pass arguments directly to the command line to configure your scan:

```bash
./target/release/netsleuth -t 192.168.1.1 -b 5 -c 24
```

- `-t, --target_ip`: Target IP address for the scan.
- `-b, --batch_size`: Number of IP addresses to scan concurrently.
- `-c, --cidr`: CIDR notation for IP range scanning.

Explore additional options and commands by viewing the help menu:

```bash
./target/release/netsleuth --help
```

## Contribution

Feel free to fork the repository, create feature branches, and send us pull requests. For major changes, please open an issue first to discuss what you would like to change.

## License

NetSleuth is licensed under the MIT License. See the LICENSE file for more details.

--- 

This README provides a straightforward overview of your project, its features, and how to install and use it. It also gives potential contributors a way to understand how they might participate in the project.
