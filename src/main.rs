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

fn main() {
    let args = Arguments::parse();

    let file_contents = fs::read(args.binary).expect("Failed to read binary");
    let elf = Elf::parse(&file_contents).expect("Failed to parse ELF");

    println!("binary entry : 0x{:x}", elf.entry);

    for ph in elf.program_headers {
        if ph.p_type == program_header::PT_LOAD && ph.is_executable() {
            println!("{:?}", ph);

            /* Read the program header */
            let mut buffer = vec![0u8; ph.p_filesz as usize];
            buffer.copy_from_slice(&file_contents[ph.file_range()]);

            /* Decode all the instruction in the program header */
            let mut decoder = Decoder::with_ip(64, &buffer, ph.p_vaddr, DecoderOptions::NONE);
            let mut instruction = Instruction::default();
            let mut formatter = NasmFormatter::new();

            /* print the instructions */
            formatter.options_mut().set_digit_separator("`");
            formatter.options_mut().set_first_operand_char_index(10);
            let mut output = String::new();

            while decoder.can_decode() {
                output.clear();
                decoder.decode_out(&mut instruction);
                formatter.format(&instruction, &mut output);
                println!("0x{:x} {}", instruction.ip(), output);
            }
        }
    }
}
