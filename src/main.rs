use netscan::scanner::HostScanner;
use netscan::setting::ScanType;
use netscan::host::{HostInfo, PortStatus};
use netscan::cross_socket::packet::PacketFrame;
use netscan::os;
use netscan::service;
use netscan::result::ScanResult;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use ipnet::Ipv4Net;
use tokio;
use std::io::{stdin, stdout, Write};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{self, Duration};
use futures::future::join_all;
use local_ip_address::local_ip;
use std::collections::HashMap;
use clap::Parser;
use clap;
use std::str::FromStr;
use std::fmt::Display;
use std::fmt;
use std::env;
use std::process::exit;

#[derive(Debug, Clone)]
struct PortRange(u16, u16);

impl FromStr for PortRange {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ports: Vec<&str> = s.split('-').collect();
        if ports.len() != 2 {
            return Err("Invalid format");
        }

        let start = ports[0].parse::<u16>().map_err(|_| "Invalid start port")?;
        let end = ports[1].parse::<u16>().map_err(|_| "Invalid end port")?;

        Ok(PortRange(start, end))
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Cli {
    #[clap(short = 't', long = "target_ip")]
    target_ip: Option<IpAddr>,

    #[clap(short = 'b', long = "batch_size", default_value = "5")]
    batch_size: usize,

    #[clap(short = 'c', long = "cidr", default_value = "24")]
    cidr: Option<u32>,

    #[clap(short = 's', long = "source_ip")]
    source_ip: Option<IpAddr>,

    #[clap(short = 'a', long = "scan_all_ip")]
    tcp_all_ip: Option<bool>,

    #[clap(short = 'i', long = "scan_ip")]
    tcp_ip: Option<IpAddr>,

    #[clap(short = 'r', long = "range")]
    range: Option<String>,
}

struct IpIterator {
    current: u32,
    end: u32,
}

impl IpIterator {
    fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self {
            current: u32::from(start),
            end: u32::from(end),
        }
    }
}

impl Iterator for IpIterator {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current <= self.end {
            let ip = Ipv4Addr::from(self.current);
            self.current += 1;
            Some(ip)
        } else {
            None
        }
    }
}

struct NetworkScanner {
    source_ip: IpAddr,
    target_start_ip: IpAddr,
    target_cidr: u32,
    batch_size: usize,
}

impl NetworkScanner {
    fn init() -> Self {
        Self {
            source_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            target_start_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            target_cidr: 0,
            batch_size: 0,
        }
    }

    fn new(source_ip: IpAddr, target_start_ip: IpAddr, target_cidr: u32, batch_size: usize) -> Self {
        Self {
            source_ip,
            target_start_ip,
            target_cidr,
            batch_size,
        }
    }

    fn get_optimized_ip_cidr(&self) -> String {
        format!("{}/{}", self.target_start_ip, self.target_cidr)
    }

    fn get_collected_ips(&self) -> Vec<Ipv4Addr> {
        let optimized_cidr = self.get_optimized_ip_cidr();
        let cidr: Ipv4Net = optimized_cidr.trim().parse().expect("Invalid CIDR");
        let start = u32::from(cidr.network());
        let end = u32::from(cidr.broadcast());
        let iterator = IpIterator::new(Ipv4Addr::from(start), Ipv4Addr::from(end));
        iterator.collect()
    }

    fn get_ip_batches(&self) -> Vec<Vec<Ipv4Addr>> {
        let collected_ips = self.get_collected_ips();
        collected_ips.chunks(self.batch_size).map(|chunk| chunk.to_vec()).collect()
    }

    async fn test_existence(src_ip: IpAddr, ip: IpAddr) -> Result<Vec<IpAddr>, String> {
        let mut host_scanner = match HostScanner::new(src_ip) {
            Ok(scanner) => scanner,
            Err(e) => panic!("Error creating scanner: {}", e),
        };

        let mut scan_setting = host_scanner.scan_setting.clone();
        scan_setting.set_scan_type(ScanType::IcmpPingScan);

        let target_ip = ip;
        let target_host = HostInfo::new_with_ip_addr(target_ip);
        scan_setting.add_target(target_host);

        host_scanner.scan_setting = scan_setting;

        host_scanner.run_scan().await;

        let scan_result = host_scanner.get_scan_result();

        let hosts = scan_result.get_hosts();

        for host in &hosts {
            println!("Host IP: {}", host);
        }
        Ok(hosts)
    }

    async fn run_scan(&self) -> Vec<IpAddr> {
        println!("\n\nStart scanning for existing IPs in Network\n\n");
        println!("Existing IPs:");

        let ip_batches = self.get_ip_batches();
        let mut handles = Vec::new();
        let mut results: Vec<IpAddr> = Vec::new();

        for batch in ip_batches {
            let src_ip = self.source_ip;
            let handle = tokio::spawn(async move {
                let mut batch_results: Vec<IpAddr> = Vec::new();
                for ip in &batch {
                    match &NetworkScanner::test_existence(src_ip, IpAddr::V4(*ip)).await {
                        Ok(hosts) => batch_results.extend(hosts),
                        Err(e) => eprintln!("Error: {}", e),
                    }
                }
                batch_results
            });
            handles.push(handle);
        }

        for handle in handles {
            match handle.await {
                Ok(batch_results) => results.extend(batch_results),
                Err(e) => eprintln!("Task panicked: {:?}", e),
            }
        }

        results
    }

    async fn get_result(&self) -> Vec<IpAddr> {
        let results = self.run_scan().await;

        self.clear().await;
        println!("Source IP: {}", self.source_ip);
        println!("Select target start IP: {}", self.target_start_ip);
        println!("Select target CIDR: {}", self.target_cidr);
        println!("\n\nFinished scanning for existing IPs in Network\n\n");
        println!("Existing IPs:");
        for host in results.clone().into_iter() {
            println!("Host IP: {}", host);
        }
        results
    }

    async fn execute_action(&self, results: Vec<IpAddr>) {
        loop {
            let action1 = "1. Scan for most used ports on all IPs";
            let action2 = "2. Scan for most used ports on specific IP";
            let action3 = "3. Scan for ports of specific range on all IPs";
            let action4 = "4. Scan for ports of specific range on specific IP";
            let action_menu = format!(
                "\n\n{}\n{}\n{}\n{}\n",
                action1, action2, action3, action4
            );

            let mut input = String::new();
            println!("{}", action_menu);
            print!("Action 1-4: ");
            stdout().flush().unwrap();
            stdin().read_line(&mut input).unwrap();

            match input.trim().parse::<i32>() {
                Ok(1) => {
                    println!("\n\nStart scanning for open ports\n\n");
                    for ip in &results {
                        self.scan_most_used_ports_for_ip(*ip).await;
                    }
                    break;
                }
                Ok(2) => {
                    print!("Enter IP: ");
                    let mut ip_input = String::new();
                    stdout().flush().unwrap();
                    stdin().read_line(&mut ip_input).unwrap();
                    let target_ip: IpAddr = ip_input.trim().parse().expect("Invalid IP address");
                    
                    println!("\n\nStart scanning for open ports\n\n");
                    self.scan_most_used_ports_for_ip(target_ip).await;
                    break;
                }
                Ok(3) => {
                    print!("Enter the start port: ");
                    let mut start_port_input = String::new();
                    stdout().flush().unwrap();
                    stdin().read_line(&mut start_port_input).unwrap();
                    let start_port: u32 =
                        start_port_input.trim().parse().expect("Invalid start port");

                    print!("Enter the end port: ");
                    let mut end_port_input = String::new();
                    stdout().flush().unwrap();
                    stdin().read_line(&mut end_port_input).unwrap();
                    let end_port: u32 = end_port_input.trim().parse().expect("Invalid end port");

                    println!("\n\nStart scanning for open ports\n\n");
                    for ip in &results {
                        self.scan_port_range_for_ip(*ip, start_port, end_port).await;
                    }
                    break;
                }
                Ok(4) => {
                    print!("Enter IP: ");
                    let mut ip_input = String::new();
                    stdout().flush().unwrap();
                    stdin().read_line(&mut ip_input).unwrap();
                    let target_ip: IpAddr = ip_input.trim().parse().expect("Invalid IP address");

                    print!("Enter the start port: ");
                    let mut start_port_input = String::new();
                    stdout().flush().unwrap();
                    stdin().read_line(&mut start_port_input).unwrap();
                    let start_port: u32 =
                        start_port_input.trim().parse().expect("Invalid start port");

                    print!("Enter the end port: ");
                    let mut end_port_input = String::new();
                    stdout().flush().unwrap();
                    stdin().read_line(&mut end_port_input).unwrap();
                    let end_port: u32 = end_port_input.trim().parse().expect("Invalid end port");

                    println!("\n\nStart scanning for open ports\n\n");
                    self.scan_port_range_for_ip(target_ip, start_port, end_port).await;
                    break;
                }
                _ => {
                    println!("Invalid input. Please enter a valid action number.");
                }
            }
        }
    }
    
    async fn clear(&self) {
        print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
    }

    async fn scan_most_used_ports_for_ip(&self, ip: IpAddr) -> HashMap<IpAddr, Vec<u16>> {
        let mut open_ports: HashMap<IpAddr, Vec<u16>> = HashMap::new();

        let relational_db_ports = [
            7210, 3306, 1521, 1830, 5432, 1433, 1434
        ];
        let nosql_db_ports = [
            8529, 7000, 7001, 9042, 5984, 9200, 9300, 
            27017, 27018, 27019, 28017, 7473, 7474, 6379, 
            8087, 8098, 8080, 28015, 29015, 7574, 8983
        ];
        let web_app_server_ports = [
            3528, 3529, 4447, 8009, 8080, 8443, 9990,
            9999, 8080, 8005, 8009, 8080, 4712, 4713, 8009, 
            8080, 8443, 9990, 9993, 5556, 7001, 7002, 8001, 
            8008, 9043, 9060, 9080, 9443
        ];
        let config_store_ports = [
            8300, 8301, 8302, 8400, 8500, 8600, 2379, 2380, 
            6443, 8080, 5050, 5051, 2181, 2888, 3888
        ];
        let protocol_ports = [
            53, 853, 20, 21, 989, 990, 80, 443, 143, 993, 543, 
            544, 749, 750, 751, 752, 753, 754, 760, 389, 137, 
            138, 139, 944, 123, 530, 514, 873, 445, 161, 162, 
            199, 22, 23, 992, 25, 465, 43,
        ];

        let all_ports: Vec<u16> = [
            relational_db_ports.as_ref(),
            nosql_db_ports.as_ref(),
            web_app_server_ports.as_ref(),
            config_store_ports.as_ref(),
            protocol_ports.as_ref(),
        ]
        .concat();

        let mut futures = Vec::new();

        for &port in &all_ports {
            let ip = ip.clone();
            let future = tokio::spawn(async move {
                let socket_addr = format!("{}:{}", ip, port);
                if let Ok(socket_addr) = socket_addr.parse::<SocketAddr>() {
                    if time::timeout(
                        Duration::from_millis(100),
                        TcpStream::connect(&socket_addr)
                    ).await.is_ok() {
                        return Some(port);
                    }
                }
                None
            });
            futures.push(future);
        }

        let results = join_all(futures).await;

        for result in results {
            match result {
                Ok(Some(port)) => {
                    // Insert the open port into the HashMap
                    open_ports.entry(ip.clone()).or_insert_with(Vec::new).push(port);
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("Task panicked with error: {:?}", e);
                }
            }
        }

        for (ip, ports) in &open_ports {
            let formatted_ip = format!("{:<15}", ip);
            let formatted_ports = ports.iter()
                .map(|&port| port.to_string())
                .collect::<Vec<String>>()
                .join(", ");
            println!("IP-Address: {}", formatted_ip);
            println!("Open ports: {}", formatted_ports);
        }

        eprintln!("Finished scanning for open ports");

        open_ports
    }

    async fn scan_port_range_for_ip(&self, ip: IpAddr, start_port: u32, end_port: u32) -> HashMap<IpAddr, Vec<u16>> {
        let mut open_ports: HashMap<IpAddr, Vec<u16>> = HashMap::new();

        println!("\n\nStart scanning for open ports\n\n");

        let mut futures = Vec::new();

        for port in start_port..=end_port {
            let ip = ip.clone();
            let future = tokio::spawn(async move {
                let socket_addr = format!("{}:{}", ip, port);
                if let Ok(socket_addr) = socket_addr.parse::<SocketAddr>() {
                    if time::timeout(
                        Duration::from_millis(100),
                        TcpStream::connect(&socket_addr)
                    ).await.is_ok() {
                        return Some(port as u16);
                    }
                }
                None
            });
            futures.push(future);
        }

        let results = join_all(futures).await;

        for result in results {
            match result {
                Ok(Some(port)) => {
                    // Insert the open port into the HashMap
                    open_ports.entry(ip.clone()).or_insert_with(Vec::new).push(port);
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("Task panicked with error: {:?}", e);
                }
            }
        }

        for (ip, ports) in &open_ports {
            let formatted_ip = format!("{:<15}", ip);
            let formatted_ports = ports.iter()
                .map(|&port| port.to_string())
                .collect::<Vec<String>>()
                .join(", ");
            println!("IP-Address: {}", formatted_ip);
            println!("Open ports: {}", formatted_ports);
        }

        eprintln!("Finished scanning for open ports");

        open_ports
    }
}

#[tokio::main]
async fn main() {

    match env::var("USER") {
        Err(e) => {
            println!("Something went wrong: {:?}", e);
            exit(2);
        }
        Ok(name) => {
            if name != "root" {
                sudo::escalate_if_needed().unwrap();
                exit(1);
            }
        }
    }

    let cli = Cli::parse();


    let target_ip = match cli.target_ip {
        Some(ip) => {
            println!("Target IP: {}", ip);
            ip
        },
        None => {
            print!("Enter the target IP address: ");
            let _ = stdout().flush();
            let mut input = String::new();
            stdin().read_line(&mut input).unwrap();
            input.trim().parse().expect("Invalid IP address")
        }
    };

    let my_local_ip = local_ip().unwrap();
    let source_ip = match cli.source_ip {
        Some(ip) => {
            println!("Source IP: {}", ip);
            ip
        },
        None => {
            println!("Source IP: {}", my_local_ip);
            my_local_ip
        },
    };

    let cidr = match cli.cidr {
        Some(value) => {
            println!("Target CIDR: {}", value);
            value
        },
        None => {
            print!("Enter the target CIDR: ");
            let _ = stdout().flush();
            let mut input = String::new();
            stdin().read_line(&mut input).unwrap();
            input.trim().parse().expect("Invalid CIDR")
        }
    };

    let batch_size = cli.batch_size;

    let network_scanner = NetworkScanner::new(source_ip, target_ip, cidr, batch_size);
    let results = network_scanner.get_result().await;

    network_scanner.execute_action(results).await;
}
