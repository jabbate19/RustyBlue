mod packet;

use packet::protocol::*;
use pcap::{Capture, Device};
use std::collections::HashMap;
use std::fmt;


fn get_wifi() -> Option<Device> {
    for interface in Device::list().unwrap() {
        if interface.name == "en0" {
            return Some(interface);
        }
    }
    None
}

fn main() {
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
        let diff_time: f64 = time;
        let data = packet.data;
        let eth = packet::ethernet::Ethernet::new(&data).unwrap();
        let dst_mac = &eth.dst;
        let src_mac = &eth.src;
        let int = match eth.ethertype {
            packet::protocol::Layer3Protocol::Unknown => None,
            x => packet::ip::IP::new(eth.payload, x),
        }.unwrap();
        let dst_ip = &int.dst;
        let src_ip = &int.src;
        
        let protocol = &int.protocol;
        let transport_data = match protocol {
            Layer4Protocol::TCP | Layer4Protocol::UDP => {
                let transport = packet::transport::Transport::new(int.payload, protocol).unwrap();
                (transport.get_tag(), transport.to_string())
            },
            Layer4Protocol::ICMP | Layer4Protocol::ICMPv6 => {
                let icmp = packet::icmp::ICMP::new(int.payload, protocol).unwrap();
                (format!("{}", protocol), icmp.to_string())
            },
            Layer4Protocol::ARP => {
                (String::from("ARP"), int.arp.unwrap().to_string())
            },
            Layer4Protocol::Unknown => (String::from("???"), String::from("???")),
        };
        println!(
            "{} | {:.9} | {} | {} | {} | {} | {}",
            i, diff_time, src_ip, dst_ip, transport_data.0, len, transport_data.1
        );
        i += 1;
    }
}
