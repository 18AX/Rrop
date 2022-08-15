use clap::Parser;
use core::panic;
use goblin::elf::*;
use iced_x86::*;
use std::fs;
mod code_gen;
mod gadget;
mod rop;

#[derive(Parser, Default, Debug)]
#[clap(version)]
struct Arguments {
    binary: String,
    #[clap(takes_value = false, short, long)]
    /// generate a ropchain
    binsh: bool,
    #[clap(takes_value = false, short, long)]
    /// generate python3 code using pwntool
    pwntool: bool,
    #[clap(short, long)]
    /// generate python3 code using pwntool
    writable_address: Option<u64>,
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

fn find_ph_from_virt_address(
    program_headers: &Vec<ProgramHeader>,
    address: u64,
) -> Result<&ProgramHeader, String> {
    for ph in program_headers {
        if address >= ph.p_vaddr && address < ph.p_vaddr + ph.p_memsz {
            return Ok(ph);
        }
    }

    Err(String::from(""))
}

fn find_writable_address(program_headers: &Vec<ProgramHeader>) -> Result<u64, String> {
    for ph in program_headers {
        if ph.p_type == program_header::PT_LOAD && ph.is_write() {
            return Ok(ph.p_vaddr);
        }
    }
    Err(String::from("Cannot find a writable address"))
}

fn main() {
    let args = Arguments::parse();

    let file_contents = fs::read(&args.binary).expect("Failed to read binary");
    let elf = Elf::parse(&file_contents).expect("Failed to parse ELF");

    let mut gadgets: Vec<gadget::Gadget> = Vec::new();

    let writable_address: u64 = match args.writable_address {
        Some(e) => e,
        None => match find_writable_address(&elf.program_headers) {
            Ok(e) => e,
            Err(e) => panic!("{}", &e),
        },
    };

    for sym in elf.syms.iter() {
        if sym.is_function() {
            let ph = match find_ph_from_virt_address(&elf.program_headers, sym.st_value) {
                Ok(e) => e,
                Err(_) => continue,
            };

            if !ph.is_executable() {
                continue;
            }

            let func_file_address = (ph.p_offset + (sym.st_value - ph.p_vaddr)) as usize;
            let end_address = func_file_address + sym.st_size as usize;

            let mut buffer = vec![0u8; sym.st_size as usize];
            buffer.copy_from_slice(&file_contents[func_file_address..end_address]);

            /* Decode all the instruction in the program header */
            let instructions = read_instructions_from_bytes(&buffer, 64, sym.st_value);

            let mut g = gadget::find_gadgets(&instructions);

            gadgets.append(&mut g);
        }
    }

    if args.binsh {
        if writable_address == 0x0 {
            panic!("Cannot find a writable address");
        }
        let ropchain = rop::binsh(&gadgets, writable_address).expect("Failed to generate ropchain");

        if args.pwntool {
            code_gen::pwntool(&args.binary, &ropchain)
        } else {
            ropchain.iter().for_each(|e| {
                println!("{}", e);
            });
        }
    } else {
        /* Print all the gadgets found */
        gadgets.iter().for_each(|g| {
            println!("{}", g);
        });
    }
}
