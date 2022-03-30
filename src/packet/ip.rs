use byteorder::{ByteOrder, LittleEndian};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::arp::Arp;
use super::protocol::*;

pub struct IP<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: Layer4,
    pub arp: Option<Arp>,
    pub payload: &'a [u8],
}

impl<'a> IP<'a> {
    pub fn new(data: &[u8], protocol: Layer3) -> Option<IP> {
        match protocol {
            Layer3::Arp => {
                let src = IpAddr::V4(Ipv4Addr::new(data[14], data[15], data[16], data[17]));
                let dst = IpAddr::V4(Ipv4Addr::new(data[24], data[25], data[26], data[27]));
                Some(IP {
                    src,
                    dst,
                    protocol: Layer4::Arp,
                    arp: Arp::new(src, dst, data),
                    payload: &data[20..],
                })
            }
            Layer3::IPv4 => Some(IP {
                src: IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15])),
                dst: IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19])),
                protocol: Layer4::from(data[9]),
                arp: None,
                payload: &data[20..],
            }),
            Layer3::IPv6 => Some(IP {
                src: IpAddr::V6(Ipv6Addr::new(
                    LittleEndian::read_u16(&[data[9], data[8]]),
                    LittleEndian::read_u16(&[data[11], data[10]]),
                    LittleEndian::read_u16(&[data[13], data[12]]),
                    LittleEndian::read_u16(&[data[15], data[14]]),
                    LittleEndian::read_u16(&[data[17], data[16]]),
                    LittleEndian::read_u16(&[data[19], data[18]]),
                    LittleEndian::read_u16(&[data[21], data[20]]),
                    LittleEndian::read_u16(&[data[23], data[22]]),
                )),
                dst: IpAddr::V6(Ipv6Addr::new(
                    // 25 24 39 38
                    LittleEndian::read_u16(&[data[25], data[24]]),
                    LittleEndian::read_u16(&[data[27], data[26]]),
                    LittleEndian::read_u16(&[data[29], data[28]]),
                    LittleEndian::read_u16(&[data[31], data[30]]),
                    LittleEndian::read_u16(&[data[33], data[32]]),
                    LittleEndian::read_u16(&[data[35], data[34]]),
                    LittleEndian::read_u16(&[data[37], data[36]]),
                    LittleEndian::read_u16(&[data[39], data[38]]),
                )),
                protocol: Layer4::from(data[6]),
                arp: None,
                payload: &data[40..],
            }),
            _ => None,
        }
    }
}

pub fn ip_network_id(ip: &str, cidr: u16) -> Option<u32> {
    let pieces = ip.split('.');
    let mut data: u32 = 0;
    let mut pos: u8 = 1;
    for piece in pieces {
        let num: u32 = piece.parse().unwrap();
        data += num;
        if pos != 4 {
            data = data << 8;
        }
        pos += 1;
    }
    let cidr = 24;
    let end = &data >> (32 - cidr);
    Some(end)
}
