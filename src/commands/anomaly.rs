use crate::packet;
use crate::packet::protocol::*;
use dns_lookup::lookup_addr;
use pcap::{Capture, Device};
use std::net::IpAddr;
use std::process::Command;
use std::vec::Vec;
use std::collections::HashSet;

use clap::ArgMatches;

pub fn anomaly(matches: &ArgMatches) {
    let killswitch: bool = matches.is_present("killswitch");
    // Get Data file with config
    let filename = matches.value_of("config").unwrap();
    let f = std::fs::File::open(filename).unwrap();
    let data: serde_yaml::Value = serde_yaml::from_reader(f).unwrap();

    let host: IpAddr = IpAddr::V4(data["host"].as_str().unwrap().parse().unwrap());

    // Read Allowed Ports
    let mut new_ports = Vec::new();
    let ports = data["ports"].as_sequence().unwrap();
    for port in ports {
        let p = port.as_u64().unwrap() as u16;
        new_ports.push(p);
    }

    // Read safe network IDs and CIDR
    let mut safe_ids = Vec::new();
    let safe = data["safe"].as_sequence().unwrap();
    for s in safe {
        let cidr = s["cidr"].as_u64().unwrap() as u16;
        safe_ids.push((
            packet::ip::ip_network_id(s["ip"].as_str().unwrap().parse().unwrap(), &cidr).unwrap(),
            cidr,
        ));
    }

    // Known Red Flags
    let mut flag_ids = Vec::new();
    let flag = data["flags"].as_sequence().unwrap();
    for f in flag {
        let cidr = f["cidr"].as_u64().unwrap() as u16;
        flag_ids.push((
            packet::ip::ip_network_id(f["ip"].as_str().unwrap().parse().unwrap(), &cidr).unwrap(),
            cidr,
        ));
    }

    println!("Host IP: {}", host);
    println!("Good Ports: {:?}", new_ports);
    println!("Safe Networks: {:?}", safe_ids);
    println!("Unsafe Networks: {:?}", flag_ids);

    let format: bool = !matches.is_present("no-format");

    let mut term = term::stdout().unwrap();
    if format {
        term.fg(term::color::BRIGHT_CYAN).unwrap();
    }
    writeln!(term, "______          _        ______ _            \n| ___ \\        | |       | ___ \\ |           \n| |_/ /   _ ___| |_ _   _| |_/ / |_   _  ___ \n|    / | | / __| __| | | | ___ \\ | | | |/ _ \\\n| |\\ \\ |_| \\__ \\ |_| |_| | |_/ / | |_| |  __/\n\\_| \\_\\__,_|___/\\__|\\__, \\____/|_|\\__,_|\\___|\n                     __/ |                   \n                    |___/                    ").unwrap();
    if format {
        term.reset().unwrap();
        term.fg(term::color::RED).unwrap();
    }
    let dev = match matches.value_of("interface") {
        Some(interface) => Device::list()
            .unwrap()
            .into_iter()
            .find(|d| d.name == interface)
            .expect("Couldn't find specified interface"),
        _ => Device::lookup().unwrap(),
    };

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

        let mut red_flag: bool = false;
        let mut reason: String = String::new();

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
        let dst_mac = &eth.dst;
        let src_mac = &eth.src;
        let int = match packet::ip::IP::new(&eth.payload, eth.ethertype) {
            Some(x) => x,
            None => continue,
        };
        let dst_ip = &int.dst;
        let src_ip = &int.src;
        if dst_ip.is_ipv4() {
            for (net_id, cidr) in &flag_ids {
                if net_id == &packet::ip::ip_network_id(*src_ip, cidr).unwrap()
                    || net_id == &packet::ip::ip_network_id(*dst_ip, cidr).unwrap()
                {
                    red_flag = true;
                    reason.push_str("FLAGGED_IP;")
                }
            }
        }
        let protocol = &int.protocol;
        let transport_data = match protocol {
            Layer4::Tcp | Layer4::Udp => {
                let transport = packet::transport::Transport::new(int.payload, protocol).unwrap();
                let port_of_concern: u16 = if &host == src_ip {
                    transport.src_port
                } else {
                    transport.dst_port
                };
                if (!new_ports.contains(&port_of_concern)) {
                    red_flag = true;
                    reason.push_str("UNAUTHORIZED_PORT");
                    if !cfg!(target_os = "windows") {
                        let process = Command::new("lsof")
                            .arg("-i")
                            .arg(&format!(":{}", port_of_concern))
                            .output()
                            .unwrap();
                        let mut lsof_out = std::str::from_utf8(&process.stdout)
                            .unwrap()
                            .split_whitespace();
                        lsof_out.next();
                        let mut pids = HashSet::new();
                        loop{
                            for i in 0..9 {
                                match lsof_out.next() {
                                    Some(_) => {},
                                    None => break
                                };
                            }
                            match lsof_out.next() {
                                Some(x) => {
                                    pids.insert(x)
                                },
                                None => break
                            };
                        }
                        if pids.len() > 0 {
                            let mut all_pids = String::from(" (PIDS: ");
                            for pid in pids {
                                all_pids.push_str(pid);
                                all_pids.push_str(",");
                                if killswitch {
                                    Command::new("kill").arg("-9").arg(pid).output();
                                }
                            }
                            all_pids.push_str(")");
                            reason.push_str(&all_pids);
                        }
                    }
                    reason.push_str(";");
                }
                (transport.get_tag(), transport.to_string())
            }
            Layer4::Icmp | Layer4::ICMPv6 => {
                let icmp = packet::icmp::Icmp::new(int.payload, protocol).unwrap();
                (format!("{}", protocol), format!("{}", icmp))
            }
            Layer4::Arp => {
                if len > 60 {
                    red_flag = true;
                    reason.push_str("LARGE_ARP_PACKET;");
                }
                (String::from("ARP"), int.arp.unwrap().to_string())
            }
            Layer4::Igmp => (String::from("IGMP"), String::from("IGMP")),
            Layer4::IPv6HopByHop => (String::from("IPv6HbH"), String::from("IPv6HbH")),
            Layer4::Unknown(x) => {
                red_flag = true;
                reason.push_str("UNKNOWN_LAYER4;");
                (String::from("???"), format!("??? (Header ID: {})", x))
            }
        };
        for (net_id, cidr) in &safe_ids {
            if (&host == src_ip && net_id == &packet::ip::ip_network_id(*dst_ip, cidr).unwrap())
                || (&host == dst_ip && net_id == &packet::ip::ip_network_id(*src_ip, cidr).unwrap())
            {
                red_flag = false;
            }
        }
        if red_flag {
            match protocol {
                Layer4::Arp => writeln!(
                    term,
                    "{} | {:.9} | {} | {} | {} | {} | {} | {}",
                    i, diff_time, src_mac, dst_mac, transport_data.0, len, transport_data.1, reason
                ),
                _ => {
                    if matches.is_present("rdns") {
                        let src_lookup = match lookup_addr(src_ip) {
                            Ok(x) => {
                                format!(" ({})", x)
                            }
                            Err(_) => String::new(),
                        };
                        let dst_lookup = match lookup_addr(dst_ip) {
                            Ok(x) => format!(" ({})", x),
                            Err(_) => String::new(),
                        };
                        writeln!(
                            term,
                            "{} | {:.9} | {}{} | {}{} | {} | {} | {} | {}",
                            i,
                            diff_time,
                            src_ip,
                            src_lookup,
                            dst_ip,
                            dst_lookup,
                            transport_data.0,
                            len,
                            transport_data.1,
                            reason
                        )
                    } else {
                        writeln!(
                            term,
                            "{} | {:.9} | {} | {} | {} | {} | {} | {}",
                            i,
                            diff_time,
                            src_ip,
                            dst_ip,
                            transport_data.0,
                            len,
                            transport_data.1,
                            reason
                        )
                    }
                }
            }
            .unwrap();
        }
        i += 1;
    }
}
