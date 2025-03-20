use clap::{Parser, Subcommand};
// use reqwest::dns::Resolve;
// Rogue Access point detector is not possible in termux: "Permission denied"
// use pcap::{Device, Capture};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use futures::future::join_all;
use reqwest::Client;
use sysinfo::Networks;
// use whois_rust::{WhoIs, WhoIsLookupOptions};
use trust_dns_resolver::{config::*, TokioAsyncResolver};

mod db;


#[derive(Parser)]
#[command(name="security")]
#[command(about = "security related CLI tool", long_about = None)]
struct Cli {
    #[arg(short, long)]
    debug: bool,

    name: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Greet {
        #[arg(short, long)]
        name: String,
    },

    Add {
        #[arg(short, long)]
        a: i32,

        #[arg(short, long)]
        b: i32,
    },

    
    #[command(about = "Scanning ports", long_about = "Scans which ports are open")]
    Scanner {
        #[arg(short, long)]
        ip: String,

        #[arg(short = 's', long, default_value_t = 1)]
        start_port: u16,
        
        #[arg(short = 'e', long, default_value_t = 65535)]
        end_port: u16,

        #[arg(short = 't', long, default_value_t = 500)]
        timeout: u64,
    },

    #[command(about = "Scanning ports", long_about = "Scans which ports are open")]
    ScanNetwork,

    #[command(about = "Display http headers", long_about = None)]
    HttpHeaders {
        #[arg(short, long)]
        url: String,
    },

    #[command(about = "Not quite working", long_about = None)]
    Whois {
        #[arg(short, long)]
        domain: String,
    },

    #[command(about = "Find IP adresses for a domain", long_about = None)]
    DnsLookup {
        #[arg(short, long)]
        domain: String,
    },

    #[command(about = "Finding subdomain of domain amongst most common ones", long_about = None)]
    Subdomain {
        #[arg(short, long)]
        domain: String
    },

    #[command(about = "Limited functionality, as api link has a usage limit", long_about = None)]
    ReverseIp {
        #[arg(short, long)]
        ip: String,
    },

    #[command(about = "Read logs", long_about = None)]
    ReadLogs,

}

async fn scan_port(ip: &str, port: u16, timeout_duration: Duration) -> Option<u16> {
    let address = format!("{}:{}", ip, port);
    match timeout(timeout_duration, TcpStream::connect(&address)).await {
        Ok(Ok(_)) => Some(port),
        _ => None,
    }
}

async fn handle_scanner(ip: String, start_port: u16, end_port: u16, timeout: u64) {
    println!(
        "scanning {} from port {}, to {} with a timeout of {} ms...",
        ip, start_port, end_port, timeout
    );
    let timeout_duration = Duration::from_millis(timeout);
    let mut tasks = vec![];
    for port in start_port..end_port {
        tasks.push(scan_port(&ip, port, timeout_duration));
    }
    let print_output = join_all(tasks).await;
    for port in print_output.into_iter().flatten() {
        println!("Port {} is open!", port);
    }
}


// should be careful using this in a high security work place
fn scan_network() {
  // let mut system = System::new_all();
  // system.refresh_all();
  let network = Networks::new(); //.refresh(&system);

  println!("Active network interfaces:");
  for (interface, _) in network.iter() {
    println!("- {}", interface);
  }
  // for (interface, data) in system.
}


async fn analyze_http_headers(url: String) {
    let client = Client::new();
    match client.get(&url).send().await {
        Ok(response) => {
            println!("HTTP Headers for {}:\n", url);
            for (key, value) in response.headers() {
                println!("{}: {:?}", key, value);
            }
        }
        Err(e) => println!("Failed to fetch headers: {}", e),
    }
}


// TODO whois lookup
async fn whois_lookup(_domain: String) {
    /*
    let whois = WhoIs::from_path("/etc/whois.conf").unwrap();
    // let options = WhoIsLookup

    
    let options = WhoIsLookupOptions

    match whois.lookup(_domain) {
        Ok(info) => println!("{}", info),
        Err(e) => println!("Whois lookup failed: {}", e),
    }
    */
}


async fn dns_lookup(domain: String) {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
//        .expect("Failed to create resolver");
//    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    match resolver.lookup_ip(domain.clone()).await {
        Ok(response) => {
            println!("IP Adresses for {}:", domain);
            for ip in response.iter() {
                println!("{}", ip);
            }
        }
        Err(_) => println!("Filed to resove domain."),
    }
}


async fn check_subdomain(subdomain: String) -> Option<String> {
    let url = format!("http://{}", subdomain);
    let client = Client::new();
    if client.get(&url).send().await.is_ok() {
        Some(subdomain) 
    } else {
            None
    }
}


async fn subdomain_enumeration(domain: String) {
    let common_subs = vec!["www", "mail", "ftp", "blog", "shop", "test", "dev", "api"];
    let tasks = common_subs.into_iter()
        .map(|sub| check_subdomain(format!("{}.{}", sub, domain)))
        .collect::<Vec<_>>();

    let outputs = join_all(tasks).await;
    for sub in outputs.into_iter().flatten() {
        println!("Found subdomain: {}", sub);
    }
}


async fn reverse_ip_lookup(ip: String) {
    let url = format!("https://api.hackertarget.com/reverseiplookup/?q={}", ip);
    let client = Client::new();

    match client.get(&url).send().await {
        Ok(resp) => {
            if let Ok(text) = resp.text().await {
                println!("Domains hosted on {}:\n{}", ip, text);
            }
        }
        Err(e) => println!("Reverse IP lookup failed: {}", e),
    }
}


#[tokio::main]
async fn main() {
    /*
    let device = Device::lookup()
        .expect("Device lookup failed")
        .expect("No device found");
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .snaplen(5000)
        .open()
        .expect("Opening of capture failed");
    
    println!("scanning rogue access points");
    while let Ok(packet) = cap.next_packet() {
        println!("Packet: {:?}", packet);
    }
    */

    // use db::*;
    let conn = db::initialize_db();
    if conn.is_err() {
        println!("Failed to initialize database, quitting process, {}", conn.err().unwrap());
        return;
    }
    let conn = conn.unwrap();

    let cli = Cli::parse();

    if cli.debug {
        println!("Debug mode is ON");
    }

    if let Some(name) = cli.name {
        println!("Hello, {}!", name);
    }

    match &cli.command {
        Some(Commands::Greet { name }) => {
            let message = format!("Hello, {}! Welocome to my CLI tool.", name);
            println!("{}", &message.as_str());
            db::log_activity(&conn, message.as_str()).unwrap();
        }
        Some(Commands::Add { a, b }) => {
            println!("The sum of {} and {} is {}", a, b, a + b);
        }
        Some(Commands::Scanner { ip, start_port, end_port, timeout } ) => {
            handle_scanner( ip.to_string(), *start_port, *end_port, *timeout).await;
        }
        Some(Commands::ScanNetwork) => {
            scan_network();
        }
        Some(Commands::HttpHeaders { url }) => {
           analyze_http_headers(url.clone()).await;
        }
        Some(Commands::Whois { domain } ) => {
            whois_lookup(domain.clone()).await;
        }
        Some(Commands::DnsLookup { domain } ) => {
            dns_lookup(domain.clone()).await;
        }
        Some(Commands::Subdomain { domain } ) => {
            subdomain_enumeration(domain.clone()).await;
        }
        Some(Commands::ReverseIp { ip } ) => {
            reverse_ip_lookup( ip.clone() ).await;
        }
        Some(Commands::ReadLogs) => {
            let result = db::read_logs(&conn);
            if result.is_err() {
                println!("Failed to read logs: {}", result.err().unwrap());
            }
        }
        None => {},
    }
}


