use std::fmt;

pub struct Arp {
    src_ip: String,
    dst_ip: String,
    src_mac: String,
    dst_mac: String,
    opcode: u16,
}

impl Arp {
    pub fn new(src_ip: String, dst_ip: String, data: &[u8]) -> Option<Arp> {
        Some(Arp {
            src_ip,
            dst_ip,
            src_mac: format!(
                "{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
                data[8], data[9], data[10], data[11], data[12], data[13]
            ),
            dst_mac: format!(
                "{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
                data[18], data[19], data[20], data[21], data[22], data[23]
            ),
            opcode: ((data[6] as u16) << 8) | data[7] as u16,
        })
    }
}

impl fmt::Display for Arp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.opcode {
            1 => write!(f, "Who has {}? Tell {}", self.dst_ip, self.src_ip),
            2 => write!(f, "{} is at {}", self.src_ip, self.src_mac),
            _ => write!(f, "ARP"),
        }
    }
}
