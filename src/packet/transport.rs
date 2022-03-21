use super::protocol::*;
use std::fmt;

pub struct Transport<'a> {
    src_port: u16,
    dst_port: u16,
    protocol: &'a Layer4,
    payload: &'a [u8],
}

impl<'a> Transport<'a> {
    pub fn new(data: &'a [u8], protocol: &'a Layer4) -> Option<Transport<'a>> {
        match protocol {
            Layer4::Tcp => Some(Transport {
                src_port: ((data[0] as u16) << 8) | data[1] as u16,
                dst_port: ((data[2] as u16) << 8) | data[3] as u16,
                protocol,
                payload: &data[20..],
            }),
            Layer4::Udp => Some(Transport {
                src_port: ((data[0] as u16) << 8) | data[1] as u16,
                dst_port: ((data[2] as u16) << 8) | data[3] as u16,
                protocol,
                payload: &data[8..],
            }),
            _ => None,
        }
    }

    pub fn get_tag(&self) -> String {
        match self.src_port {
            20..=21 => String::from("FTP"),
            22 => String::from("SSH"),
            25 => String::from("SMTP"),
            53 => String::from("DNS"),
            67 => String::from("DHCP"),
            68 => String::from("DHCP"),
            80 => String::from("HTTP"),
            110 => String::from("POP3"),
            143 => String::from("IMAP"),
            443 => String::from("HTTPS"),
            5353 => String::from("MDNS"),
            _ => match self.dst_port {
                20..=21 => String::from("FTP"),
                22 => String::from("SSH"),
                25 => String::from("SMTP"),
                53 => String::from("DNS"),
                67 => String::from("DHCP"),
                68 => String::from("DHCP"),
                80 => String::from("HTTP"),
                110 => String::from("POP3"),
                143 => String::from("IMAP"),
                443 => String::from("HTTPS"),
                5353 => String::from("MDNS"),
                _ => format!("{}", self.protocol),
            },
        }
    }

    pub fn get_color(&self) -> term::color::Color {
        let tag = &self.get_tag()[..];
        match tag {
            "FTP" => term::color::WHITE,
            "SSH" => term::color::WHITE,
            "SMTP" => term::color::WHITE,
            "DNS" => term::color::CYAN,
            "DHCP" => term::color::WHITE,
            "HTTP" => term::color::GREEN,
            "POP3" => term::color::WHITE,
            "IMAP" => term::color::WHITE,
            "HTTPS" => term::color::GREEN,
            "MDNS" => term::color::CYAN,
            _ => match &self.protocol {
                Layer4::Tcp => term::color::BRIGHT_CYAN,
                Layer4::Udp => term::color::CYAN,
                _ => term::color::RED,
            },
        }
    }
}

impl std::fmt::Display for Transport<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tag = &self.get_tag()[..];
        let out = match tag {
            "FTP" => String::from("FTP Data"),
            "SSH" => String::from("SSH Data"),
            "SMTP" => String::from("SMTP Data"),
            "DNS" => String::from("DNS Data"),
            "DHCP" => String::from("DHCP Data"),
            "HTTP" => String::from("HTTP Data"),
            "POP3" => String::from("POP3 Data"),
            "IMAP" => String::from("IMAP Data"),
            "HTTPS" => String::from("HTTPS Data"),
            "MDNS" => String::from("MDNS Data"),
            _ => String::new(),
        };
        let port_dir = format!("{} -> {}", self.src_port, self.dst_port);
        match out.len() {
            0 => write!(f, "{}", port_dir),
            _ => write!(f, "{} ({})", out, port_dir),
        }
    }
}
