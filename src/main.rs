use pcap::{Capture, Device};
use std::collections::HashMap;
use std::fmt;

enum Layer3Protocol {
    IPv4,
    IPv6,
    ARP,
    VLAN,
}

enum IPProtocol {
    TCP,
    UDP,
    ICMP,
    ICMPv6,
}

impl fmt::Display for IPProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IPProtocol::TCP => write!(f, "TCP"),
            IPProtocol::UDP => write!(f, "UDP"),
            IPProtocol::ICMP => write!(f, "ICMP"),
            IPProtocol::ICMPv6 => write!(f, "ICMPv6"),
        }
    }
}

fn get_wifi() -> Option<Device> {
    for interface in Device::list().unwrap() {
        if interface.name == "en0" {
            return Some(interface);
        }
    }
    None
}

fn main() {
    let layer_3_protocols = HashMap::from([
        ([8, 0], Layer3Protocol::IPv4),
        ([8, 6], Layer3Protocol::ARP),
        ([134, 221], Layer3Protocol::IPv6),
        ([129, 0], Layer3Protocol::VLAN),
    ]);

    let ip_protocols = HashMap::from([
        (6, IPProtocol::TCP),
        (17, IPProtocol::UDP),
        (1, IPProtocol::ICMP),
        (58, IPProtocol::ICMPv6),
    ]);
    println!("Running!");
    let dev = get_wifi().unwrap();
    let mut capture = Capture::from_device(dev).unwrap().open().unwrap();
    let mut i: u64 = 1;
    let mut start_time: f64 = 0.0;
    loop {
        let packet = capture.next().unwrap();
        let time: f64 = format!("{}.{}", packet.header.ts.tv_sec, packet.header.ts.tv_usec)
            .parse()
            .unwrap();
        let len = packet.header.len;
        if i == 1 {
            start_time = time;
        }
        //let diff_time: f64 = time - start_time;
        let diff_time: f64 = time;
        let data = packet.data;
        let dst_mac = format!(
            "{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
            data[0], data[1], data[2], data[3], data[4], data[5]
        );
        let src_mac = format!(
            "{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
            data[6], data[7], data[8], data[9], data[10], data[11]
        );
        match layer_3_protocols.get(&data[12..14]) {
            Some(Layer3Protocol::IPv4) => {
                let mut src_ip = format!("{}.{}.{}.{}", data[26], data[27], data[28], data[29]);
                for _ in 0..(39 - src_ip.len()) {
                    src_ip.push_str(" ");
                }
                let mut dst_ip = format!("{}.{}.{}.{}", data[30], data[31], data[32], data[33]);
                for _ in 0..(39 - dst_ip.len()) {
                    dst_ip.push_str(" ");
                }
                let protocol = match ip_protocols.get(&data[23]) {
                    Some(x) => x.to_string(),
                    None => String::from("???"),
                };
                println!(
                    "{} | {:.9} | {} | {} | {} | {}",
                    i, diff_time, src_ip, dst_ip, protocol, len
                );
            }
            Some(Layer3Protocol::IPv6) => {
                let mut src_ip = String::new();
                for i in (22..38).step_by(2) {
                    let a = format!("{:X?}", data[i]);
                    let b = format!("{:X?}", data[i + 1]);
                    if a.eq("0") {
                        if b.eq("0") {
                            src_ip.push_str("0:");
                        } else {
                            src_ip.push_str(&b);
                            src_ip.push_str(":");
                        }
                    } else {
                        src_ip.push_str(&a);
                        src_ip.push_str(&b);
                        src_ip.push_str(":");
                    }
                }
                for _ in 0..(39 - src_ip.len()) {
                    src_ip.push_str(" ");
                }
                let mut dst_ip = String::new();
                for i in (38..54).step_by(2) {
                    let a = format!("{:X?}", data[i]);
                    let b = format!("{:X?}", data[i + 1]);
                    if a.eq("0") {
                        if b.eq("0") {
                            dst_ip.push_str("0:");
                        } else {
                            dst_ip.push_str(&b);
                            dst_ip.push_str(":");
                        }
                    } else {
                        dst_ip.push_str(&a);
                        dst_ip.push_str(&b);
                        dst_ip.push_str(":");
                    }
                }
                for _ in 0..(39 - dst_ip.len()) {
                    src_ip.push_str(" ");
                }
                let protocol = match ip_protocols.get(&data[20]) {
                    Some(x) => x.to_string(),
                    None => String::from("???"),
                };
                println!(
                    "{} | {:.9} | {} | {} | {} | {}",
                    i,
                    diff_time,
                    src_ip,
                    dst_ip,
                    protocol,
                    len
                );
            }
            Some(Layer3Protocol::ARP) => {
                println!(
                    "{} | {:.9} | {} | {} | ARP | {}",
                    i, diff_time, src_mac, dst_mac, len
                );
            }
            Some(Layer3Protocol::VLAN) => {
                println!("{} | {:.9} | VLAN Data | {}", i, diff_time, len);
            }
            None => {
                println!(
                    "{} | {:.9} | Unknown Layer 3 Protocol | {}",
                    i, diff_time, len
                );
            }
        }
        if data[12] == 8 && data[13] == 0 {
        } else {
        }
        //println!("{} | {} | {:?}", i, diff_time, &data[..50]);
        i += 1;
    }
}
