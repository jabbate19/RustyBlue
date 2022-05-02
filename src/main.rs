mod commands;
mod packet;

use clap::{Arg, ArgMatches, Command};

fn main() {
    let matches = Command::new("RustyBlue")
        .about("Rust-Based CLI Blue Team Tool")
        .subcommand(
            Command::new("init")
                .about("initialize 5 minute plan and template file")
        )
        .subcommand(
            Command::new("sniff")
                .about("sniff traffic with given filters")
                .arg(
                    Arg::new("interface")
                        .short('i')
                        .long("interface")
                        .takes_value(true)
                        .help("Specific interface to sniff")
                        .required(false),
                )
                .arg(
                    Arg::new("mac")
                        .short('m')
                        .takes_value(true)
                        .help("MAC Filter to apply to data")
                        .required(false),
                )
                .arg(
                    Arg::new("ip")
                        .short('p')
                        .takes_value(true)
                        .help("IP Filter to apply to data. Can be iPv6 or iPv4")
                        .required(false),
                )
                .arg(
                    Arg::new("no-format")
                        .long("no-format")
                        .takes_value(false)
                        .help("Disables colors in output")
                        .required(false),
                )
                .arg(
                    Arg::new("rdns")
                        .short('d')
                        .takes_value(false)
                        .help("Attaches DNS lookup to IP")
                        .required(false),
                ),
        )
        .subcommand(
            Command::new("anomaly")
                .about("search for data that seems a-typical to the given setup")
                .arg(
                    Arg::new("config")
                        .index(1)
                        .help("Config file of the given device")
                        .required(true),
                )
                .arg(
                    Arg::new("interface")
                        .short('i')
                        .long("interface")
                        .takes_value(true)
                        .help("Specific interface to sniff")
                        .required(false),
                )
                .arg(
                    Arg::new("no-format")
                        .long("no-format")
                        .takes_value(false)
                        .help("Disables colors in output")
                        .required(false),
                )
                .arg(
                    Arg::new("rdns")
                        .short('d')
                        .takes_value(false)
                        .help("Attaches DNS lookup to IP")
                        .required(false),
                ).arg(
                    Arg::new("killswitch")
                        .short('k')
                        .takes_value(false)
                        .help("Automatically kills processes operating on unauthroized ports (BE CAREFUL)")
                        .required(false),
                ),
        )
        .get_matches();
    process_command(matches);
}

fn process_command(matches: ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("sniff") {
        commands::sniff::sniff(matches)
    } else if let Some(matches) = matches.subcommand_matches("anomaly") {
        commands::anomaly::anomaly(matches)
    } else if let Some(matches) = matches.subcommand_matches("init") {
        commands::init::init(matches)
    } else {
        println!("Please Provide a Command!");
    }
}
