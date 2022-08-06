use clap::Parser;
use goblin::elf::*;
use std::fs;

#[derive(Parser, Default, Debug)]
#[clap(version)]
struct Arguments {
    binary: String,
    #[clap(takes_value = false, short, long)]
    /// generate a ropchain
    ropchain: bool,
}

fn main() {
    let args = Arguments::parse();

    let file_contents = fs::read(args.binary).expect("Failed to read binary");
    let elf = Elf::parse(&file_contents).expect("Failed to parse ELF");

    println!("binary entry : 0x{:x}", elf.entry);
}
