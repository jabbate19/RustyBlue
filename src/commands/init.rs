use serde::{Deserialize, Serialize};
use clap::ArgMatches;
use std::io;
use std::process::Command;
use std::str;
use std::fs::File;
use std::io::Write;

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    ip: String,
    ports: Vec<u16>,
    users: Vec<String>,
    services: Vec<String>,
}

pub fn init(matches: &ArgMatches) {
    let mut term = term::stdout().unwrap();
    let mut stdin = io::stdin();
    term.fg(term::color::BRIGHT_CYAN).unwrap();
    writeln!(term, "______          _        ______ _            \n| ___ \\        | |       | ___ \\ |           \n| |_/ /   _ ___| |_ _   _| |_/ / |_   _  ___ \n|    / | | / __| __| | | | ___ \\ | | | |/ _ \\\n| |\\ \\ |_| \\__ \\ |_| |_| | |_/ / | |_| |  __/\n\\_| \\_\\__,_|___/\\__|\\__, \\____/|_|\\__,_|\\___|\n                     __/ |                   \n                    |___/                    ").unwrap();

    term.reset();
    write!(term, "Enter IP Address: ");
    term.flush();
    
    let mut ip = String::new();
    stdin.read_line(&mut ip);
    let ip = String::from(ip.trim());

    let mut ports: Vec<u16> = Vec::new();
    loop {
        write!(term, "Enter Service Port: ");
        term.flush();
        let mut port_str = String::new();
        stdin.read_line(&mut port_str);
        let port_str = port_str.trim();
        if port_str.len() == 0 {
            break;
        }
        ports.push(port_str.parse().unwrap());
    }

    let passwd = Command::new("cat")
            .arg("/etc/passwd")
            .output()
            .expect("failed to execute cat /etc/passwd");

    let mut users: Vec<String> = Vec::new();

    for line in str::from_utf8(&passwd.stdout).unwrap().lines() {
        let split = match line.find(":") {
            Some(x) => x,
            None => {continue;}
        };
        let user = &line[..split];
        if !(line.contains("/false") || line.contains("/nologin")) {
            writeln!(term, "{}", line);
            loop {
                write!(term, "Disable Account? [y/n] ");
                term.flush();
                let mut yes_or_no = String::new();
                stdin.read_line(&mut yes_or_no);
                if yes_or_no.trim().to_lowercase() == "y" {
                    Command::new("usermod")
                        .arg("-L")
                        .arg("")
                        .output()
                        .expect("failed to execute usermod -L");
                    Command::new("usermod")
                        .arg("-s")
                        .arg("/bin/false")
                        .output()
                        .expect("failed to execute usermod -s /bin/false");
                    break;
                } else if yes_or_no.trim().to_lowercase() == "n" {
                    users.push(String::from(user));
                    break;
                }
            }
        }
    }

    let mut services: Vec<String> = Vec::new();
    loop {
        write!(term, "Enter Service File to Keep Alive: ");
        term.flush();
        let mut service = String::new();
        stdin.read_line(&mut service);
        let service = service.trim();
        if service.len() == 0 {
            break;
        }
        services.push(String::from(service));
    }

    let config = Config {
        ip,
        ports,
        users,
        services
    };

    let mut out_file = File::create("config.json").unwrap();
    out_file.write_all(serde_json::to_string(&config).unwrap().as_bytes());


}