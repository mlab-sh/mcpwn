//! `mcpwn`: thin shell around the analysis engine: parse args, run the
//! `Analyzer`, render, pick an exit code.

#![warn(clippy::all)]
#![deny(unsafe_code)]

mod cli;

use clap::Parser;

fn main() {
    let code = match cli::Cli::parse().run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("mcpwn: {err:#}");
            cli::exit::ERROR
        }
    };
    std::process::exit(code);
}
