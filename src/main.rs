mod cli;
mod ui;

use crate::cli::command;
use std::process::exit;

fn main() {
    match command::run() {
        Err(e) => {
            eprintln!("{}", e);
            exit(1)
        }
        _ => {}
    }
}
