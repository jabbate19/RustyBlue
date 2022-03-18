mod packet;

use packet::protocol::*;
use pcap::{Capture, Device};

fn get_wifi() -> Option<Device> {
    for interface in Device::list().unwrap() {
        if interface.name == "en0" {
            return Some(interface);
        }
    }
    None
}

fn main() {
    let mut term = term::stdout().unwrap();
    term.fg(term::color::BRIGHT_CYAN).unwrap();
    writeln!(term, "______          _        ______ _            \n| ___ \\        | |       | ___ \\ |           \n| |_/ /   _ ___| |_ _   _| |_/ / |_   _  ___ \n|    / | | / __| __| | | | ___ \\ | | | |/ _ \\\n| |\\ \\ |_| \\__ \\ |_| |_| | |_/ / | |_| |  __/\n\\_| \\_\\__,_|___/\\__|\\__, \\____/|_|\\__,_|\\___|\n                     __/ |                   \n                    |___/                    ").unwrap();
    term.reset().unwrap();
    let dev = get_wifi().unwrap();
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
        let data = packet.data;
        let eth = packet::ethernet::Ethernet::new(data).unwrap();
        let dst_mac = &eth.dst;
        let src_mac = &eth.src;
        let int = match eth.ethertype {
            packet::protocol::Layer3Protocol::Unknown => None,
            x => packet::ip::IP::new(eth.payload, x),
        }
        .unwrap();
        let dst_ip = &int.dst;
        let src_ip = &int.src;

        let protocol = &int.protocol;
        let transport_data = match protocol {
            Layer4Protocol::Tcp | Layer4Protocol::Udp => {
                let transport = packet::transport::Transport::new(int.payload, protocol).unwrap();
                term.fg(transport.get_color()).unwrap();
                (transport.get_tag(), transport.to_string())
            }
            Layer4Protocol::Icmp | Layer4Protocol::ICMPv6 => {
                term.fg(term::color::BRIGHT_MAGENTA).unwrap();
                let icmp = packet::icmp::Icmp::new(int.payload, protocol).unwrap();
                (format!("{}", protocol), format!("{}", icmp))
            }
            Layer4Protocol::Arp => {
                term.fg(term::color::YELLOW).unwrap();
                (String::from("ARP"), int.arp.unwrap().to_string())
            }
            Layer4Protocol::Unknown => {
                term.fg(term::color::RED).unwrap();
                (String::from("???"), String::from("???"))
            }
        };
        match protocol {
            Layer4Protocol::Arp => writeln!(
                term,
                "{} | {:.9} | {} | {} | {} | {} | {}",
                i, diff_time, src_mac, dst_mac, transport_data.0, len, transport_data.1
            ),
            _ => writeln!(
                term,
                "{} | {:.9} | {} | {} | {} | {} | {}",
                i, diff_time, src_ip, dst_ip, transport_data.0, len, transport_data.1
            ),
        }
        .unwrap();
        term.reset().unwrap();
        i += 1;
    }
}
