use crate::packet;
use crate::packet::protocol::*;
use dns_lookup::lookup_addr;
use pcap::{Capture, Device};
use std::net::{IpAddr};

use clap::ArgMatches;

pub fn sniff(matches: &ArgMatches) {
    let format: bool = !matches.is_present("no-format");
    let mut term = term::stdout().unwrap();
    if format {
        term.fg(term::color::BRIGHT_CYAN).unwrap();
    }
    writeln!(term, "______          _        ______ _            \n| ___ \\        | |       | ___ \\ |           \n| |_/ /   _ ___| |_ _   _| |_/ / |_   _  ___ \n|    / | | / __| __| | | | ___ \\ | | | |/ _ \\\n| |\\ \\ |_| \\__ \\ |_| |_| | |_/ / | |_| |  __/\n\\_| \\_\\__,_|___/\\__|\\__, \\____/|_|\\__,_|\\___|\n                     __/ |                   \n                    |___/                    ").unwrap();
    term.reset().unwrap();

    let dev = match matches.value_of("interface") {
        Some(interface) => Device::list()
            .unwrap()
            .into_iter()
            .find(|d| d.name == interface)
            .expect("Couldn't find specified interface"),
        _ => Device::lookup().unwrap(),
    };

    if let Some(val) = matches.value_of("mac") {
        println!("MAC FILTER: {}", val);
    }
    if let Some(val) = matches.value_of("ip") {
        println!("IP FILTER: {}", val);
    }

    let mut capture = Capture::from_device(dev)
        .unwrap()
        .timeout(2500)
        .open()
        .unwrap();

    let mut i: u64 = 1;
    let mut start_time: f64 = 0.0;

    loop {
        let packet = match capture.next() {
            Ok(x) => x,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => {
                println!("Unknown Error in getting next packet");
                continue;
            }
        };
        let time: f64 = format!("{}.{}", packet.header.ts.tv_sec, packet.header.ts.tv_usec)
            .parse()
            .unwrap();
        let len = packet.header.len;
        if i == 1 {
            start_time = time;
        }
        let diff_time: f64 = time - start_time;
        let data = packet.data.to_vec();
        // let eth = packet::ethernet::Ethernet::new(data).unwrap();
        let eth = packet::ethernet::Ethernet::try_from(data).unwrap();
        let dst_mac = eth.dst;
        let src_mac = eth.src;
        if let Some(val) = matches.value_of("mac") {
            let filter_mac = packet::ethernet::MacAddr::from(String::from(val));
            if src_mac != filter_mac && dst_mac != filter_mac {
                continue;
            }
        }
        let int = packet::ip::IP::new(&eth.payload, eth.ethertype).unwrap();
        let dst_ip = int.dst;
        let src_ip = int.src;
        if let Some(val) = matches.value_of("ip") {
            let filter_ip: IpAddr = std::net::IpAddr::V4(val.parse().unwrap());
            if src_ip != filter_ip && dst_ip != filter_ip {
                continue;
            }
        }
        let protocol = &int.protocol;
        let transport_data = match protocol {
            Layer4::Tcp | Layer4::Udp => {
                let transport = packet::transport::Transport::new(int.payload, protocol).unwrap();
                if format {
                    term.fg(transport.get_color()).unwrap();
                }
                (transport.get_tag(), transport.to_string())
            }
            Layer4::Icmp | Layer4::ICMPv6 => {
                if format {
                    term.fg(term::color::BRIGHT_MAGENTA).unwrap();
                }
                let icmp = packet::icmp::Icmp::new(int.payload, protocol).unwrap();
                (format!("{}", protocol), format!("{}", icmp))
            }
            Layer4::Arp => {
                if format {
                    term.fg(term::color::YELLOW).unwrap();
                }
                (String::from("ARP"), int.arp.unwrap().to_string())
            }
            Layer4::Unknown(_) => {
                if format {
                    term.fg(term::color::RED).unwrap();
                }
                (String::from("???"), String::from("???"))
            }
        };

        match protocol {
            Layer4::Arp => writeln!(
                term,
                "{} | {:.9} | {} | {} | {} | {} | {}",
                i, diff_time, src_mac, dst_mac, transport_data.0, len, transport_data.1
            ),
            _ => {
                if matches.is_present("rdns") {
                    let src_lookup = match lookup_addr(&src_ip) {
                        Ok(x) => {
                            format!(" ({})", x)
                        }
                        Err(_) => String::new(),
                    };
                    let dst_lookup = match lookup_addr(&dst_ip) {
                        Ok(x) => format!(" ({})", x),
                        Err(_) => String::new(),
                    };
                    writeln!(
                        term,
                        "{} | {:.9} | {}{} | {}{} | {} | {} | {}",
                        i,
                        diff_time,
                        src_ip,
                        src_lookup,
                        dst_ip,
                        dst_lookup,
                        transport_data.0,
                        len,
                        transport_data.1
                    )
                } else {
                    writeln!(
                        term,
                        "{} | {:.9} | {} | {} | {} | {} | {}",
                        i, diff_time, src_ip, dst_ip, transport_data.0, len, transport_data.1
                    )
                }
            }
        }
        .unwrap();

        term.reset().unwrap();
        i += 1;
    }
}
