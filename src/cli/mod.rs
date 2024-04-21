mod base64;
mod csv;
mod genpass;

use std::path::Path;

use self::{csv::CsvOpts, genpass::GenPassOpts};
use clap::Parser;

pub use self::{
    base64::{Base64Format, Base64SubCommand},
    csv::OutputFormat,
};

#[derive(Debug, Parser)]
#[command(name = "rcli", version, author, about, long_about = None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Debug, Parser)]
pub enum SubCommand {
    #[command(name = "csv", about = "Show CSV, or Convert to other formats")]
    Csv(CsvOpts),
    #[command(name = "genpass", about = "Generate a random password")]
    GenPass(GenPassOpts),
    #[command(subcommand)]
    Base64(Base64SubCommand),
}

fn valify_input_file(filename: &str) -> Result<String, &'static str> {
    // if input os "-" or file exits
    if filename == "-" || Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err("File does not exist")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valify_input_file() {
        assert_eq!(valify_input_file("-"), Ok("-".into()));
        assert_eq!(valify_input_file("Cargo.toml"), Ok("Cargo.toml".into()));
        assert_eq!(
            valify_input_file("not-exist.csv"),
            Err("File does not exist")
        );
    }
}
