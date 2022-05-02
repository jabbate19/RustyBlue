use clap::ArgMatches;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::io::Write;
use std::io::{BufRead, BufWriter, Write};
use std::process::Command;
use std::str;

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

    term.fg(term::color::YELLOW).unwrap();
    writeln!(term, "Writing Firewall...");
    term.reset();

    Command::new("iptables")
        .arg("-F")
        .output()
        .expect("failed to flush iptables");

    Command::new("iptables")
        .arg("-P")
        .arg("INPUT")
        .arg("DROP")
        .output()
        .expect("failed to set default DROP to iptables INPUT");

    Command::new("iptables")
        .arg("-P")
        .arg("OUTPUT")
        .arg("DROP")
        .output()
        .expect("failed to set default DROP to iptables OUTPUT");

    Command::new("iptables")
        .arg("-P")
        .arg("FORWARD")
        .arg("DROP")
        .output()
        .expect("failed to set default DROP to iptables FORWARD");

    Command::new("iptables")
        .arg("-A")
        .arg("INPUT")
        .arg("-p")
        .arg("icmp")
        .arg("-j")
        .arg("ACCEPT")
        .output()
        .expect("failed to set allow ICMP");

    for port in &ports {
        Command::new("iptables")
            .arg("-A")
            .arg("INPUT")
            .arg("-p")
            .arg("tcp")
            .arg("--dport")
            .arg(port.to_string())
            .arg("-j")
            .arg("ACCEPT")
            .output()
            .expect("failed to set port allow");
    }

    term.fg(term::color::BRIGHT_GREEN).unwrap();
    writeln!(term, "Successfully Wrote iptables rules!");
    term.reset();

    let passwd = Command::new("cat")
        .arg("/etc/passwd")
        .output()
        .expect("failed to execute cat /etc/passwd");

    let mut users: Vec<String> = Vec::new();

    for line in str::from_utf8(&passwd.stdout).unwrap().lines() {
        let split = match line.find(":") {
            Some(x) => x,
            None => {
                continue;
            }
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
                        .arg(user)
                        .output()
                        .expect("failed to execute usermod -L");
                    
                    Command::new("usermod")
                        .arg("-s")
                        .arg("/bin/false")
                        .output()
                        .expect("failed to execute usermod -s /bin/false");
                    
                    Command::new("crobtab")
                        .arg("-u")
                        .arg(user)
                        .arg("-r")
                        .output()
                        .expect("failed to execute crontab -r");

                    term.fg(term::color::BRIGHT_GREEN).unwrap();
                    writeln!(term, "User Disabled!");
                    term.reset();
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
        services,
    };

    let mut out_file = File::create("config.json").unwrap();
    out_file
        .write_all(serde_json::to_string(&config).unwrap().as_bytes())
        .unwrap();

    term.fg(term::color::BRIGHT_GREEN).unwrap();
    writeln!(term, "Successfully wrote config to config.json!");
    term.reset();

    let mut sshd_config = File::open("/etc/ssh/sshd_config").unwrap();
    let new_file = fs::File::create("/tmp/sshd_config").expect("Failed to create file");
    let mut buffered_out = BufWriter::new(new_file);
    let buffered = io::BufReader::new(old_file);
    let mut permit_root = false;
    let mut use_pam = false;
    let mut permit_empty_pass = false;

    buffered
        .lines()
        .map(|line_res| {
            line_res.and_then(|line| {
                if line.trim() == "PermitRootLogin yes" {
                    buffered_out.write_all(
                        line.replace("PermitRootLogin yes", "PermitRootLogin no")
                            .as_bytes(),
                    );
                    permit_root = true;
                } else if line.trim() == "UsePAM yes" {
                    buffered_out.write_all(line.replace("UsePAM yes", "UsePAM no").as_bytes());
                    use_pam = true;
                } else if line.trim() == "PermitEmptyPasswords yes" {
                    buffered_out.write_all(
                        line.replace("PermitEmptyPasswords yes", "PermitEmptyPasswords no")
                            .as_bytes(),
                    );
                    permit_empty_pass = true;
                } else {
                    buffered_out.write_all(line.as_bytes());
                }
            })
        })
        .collect::<Result<(), _>>()
        .expect("IO failed");

    if !permit_root {
        buffered_out.write_all(b"PermitRootLogin no");
    }

    if !use_pam {
        buffered_out.write_all(b"UsePAM no");
    }

    if !permit_empty_pass {
        buffered_out.write_all(b"PermitEmptyPasswords no");
    }

    Command::new("mv")
        .arg("/tmp/sshd_config")
        .arg("/etc/ssh/sshd_config")
        .output()
        .expect("failed to move sshd_config edits");

    Command::new("systemctl")
        .arg("restart")
        .arg("sshd")
        .output()
        .expect("failed to restart sshd");

    term.fg(term::color::BRIGHT_GREEN).unwrap();
    writeln!(term, "Successfully configured sshd_config!");
    term.reset();
    
    writeln!(term, "FILES TO CHECK NOW");
    writeln!(term, "=".repeat(20));
    writeln!(term, "/etc/sudoers (visudo)");
    writeln!(term, "~/.bashrc, ~/.bash_profile, /etc/profile, /etc/bash.bashrc");
    writeln!(term, "/etc/environment");
    writeln!(term, "/etc/inputrc");
    writeln!(term, "/etc/pam.d");
    writeln!(term, "crontab -l for ROOT AND ACTIVE USERS");
    writeln!(term, "Go Scrollin in Services for a bit (or let me do it)");
    writeln!(term, "\n\nGood Luck Agent.");

    term.flush();
    term.reset();
}
