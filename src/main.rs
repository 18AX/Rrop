use clap::Parser;
use goblin::elf::*;
use iced_x86::*;
use std::fs;
mod gadget;

#[derive(Parser, Default, Debug)]
#[clap(version)]
struct Arguments {
    binary: String,
    #[clap(takes_value = false, short, long)]
    /// generate a ropchain
    ropchain: bool,
}

fn read_instructions_from_bytes(buffer: &Vec<u8>, bitness: u32, ip: u64) -> Vec<Instruction> {
    let mut instructions = Vec::new();

    let mut decoder = Decoder::with_ip(bitness, &buffer, ip, DecoderOptions::NONE);

    while decoder.can_decode() {
        let instruction = decoder.decode();
        instructions.push(instruction);
    }

    instructions
}

fn main() {
    let args = Arguments::parse();

    let file_contents = fs::read(args.binary).expect("Failed to read binary");
    let elf = Elf::parse(&file_contents).expect("Failed to parse ELF");

    let mut gadgets: Vec<gadget::Gadget> = Vec::new();

    for ph in elf.program_headers {
        /* We are only looking for headers which are loaded and executable */
        if ph.p_type == program_header::PT_LOAD && ph.is_executable() {
            /* Read the program header */
            let mut buffer = vec![0u8; ph.p_filesz as usize];
            buffer.copy_from_slice(&file_contents[ph.file_range()]);

            /* Decode all the instruction in the program header */
            let instructions = read_instructions_from_bytes(&buffer, 64, ph.p_vaddr);

            let mut g = gadget::find_gadgets(&instructions);

            gadgets.append(&mut g);
        }
    }

    /* Print all the gadgets found */
    gadgets.iter().for_each(|g| {
        println!("{}", g);
    });
}
