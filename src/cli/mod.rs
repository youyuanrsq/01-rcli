mod base64;
mod csv;
mod genpass;
mod http;
mod text;

use std::path::{self, Path};

use self::{csv::CsvOpts, genpass::GenPassOpts};
use clap::Parser;

pub use self::{
    base64::{Base64Format, Base64SubCommand},
    csv::OutputFormat,
    http::HttpSubCommand,
    text::{TextSignFormat, TextSubCommand},
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
    #[command(subcommand, about = "Base64 encode/decode")]
    Base64(Base64SubCommand),
    #[command(subcommand, about = "Text sign/verify")]
    Text(text::TextSubCommand),
    #[command(subcommand, about = "HTTP server")]
    Http(http::HttpSubCommand),
}

fn valify_file(filename: &str) -> Result<String, &'static str> {
    // if input os "-" or file exits
    if filename == "-" || Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err("File does not exist")
    }
}

fn valify_path(path: &str) -> Result<path::PathBuf, &'static str> {
    let p = Path::new(path);
    if p.exists() && p.is_dir() {
        Ok(path.into())
    } else {
        Err("File does not exist and is not a directory")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valify_input_file() {
        assert_eq!(valify_file("-"), Ok("-".into()));
        assert_eq!(valify_file("Cargo.toml"), Ok("Cargo.toml".into()));
        assert_eq!(valify_file("not-exist.csv"), Err("File does not exist"));
    }
}
