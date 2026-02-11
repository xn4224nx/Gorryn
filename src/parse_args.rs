/*
 * Process comand line arguments given to the program and give the relevant data
 * to the rest of the program.
 *
 */

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version = "0.1", about = "Tricorder", long_about = None)]
struct ProgArgs {
    /// The root domain to be investigated.
    root_domain: String,
}

pub fn get() -> String {
    return ProgArgs::parse().root_domain;
}
