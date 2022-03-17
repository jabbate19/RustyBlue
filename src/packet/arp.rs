pub struct ARP {
    src_mac: String,
    dst_mac: String,
    opcode: u16,
}

impl ARP {
    pub fn new(data: &[u8]) -> Option<ARP> {
        None
    }
}