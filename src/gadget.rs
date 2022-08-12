use iced_x86::*;

pub struct Gadget {
    pub instructions: Vec<Instruction>,
}

impl Gadget {
    pub fn default() -> Self {
        Gadget {
            instructions: Vec::new(),
        }
    }
}

fn build_gadget(instructions: &Vec<Instruction>, position: usize) -> Gadget {
    let mut gadget = Gadget {
        instructions: Vec::new(),
    };

    for i in (0..position + 1).rev() {
        let mnem = instructions[i].mnemonic();

        if mnem != Mnemonic::Pop
            && mnem != Mnemonic::Leave
            && mnem != Mnemonic::Ret
            && mnem != Mnemonic::Retf
            && mnem != Mnemonic::Mov
            && mnem != Mnemonic::Add
            && mnem != Mnemonic::Sub
            && mnem != Mnemonic::Int
            && mnem != Mnemonic::Syscall
        {
            break;
        }

        gadget.instructions.push(instructions[i].clone());
    }

    gadget
}

pub fn find_gadgets(instructions: &Vec<Instruction>) -> Vec<Gadget> {
    let mut gadgets = Vec::new();

    for i in 0..instructions.len() {
        if instructions[i].mnemonic() == Mnemonic::Ret
            || instructions[i].mnemonic() == Mnemonic::Retf
        {
            let g = build_gadget(instructions, i);

            if g.instructions.len() > 1 {
                gadgets.push(g);
            }
        }
    }

    gadgets
}

impl std::fmt::Display for Gadget {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.instructions.len() < 1 {
            return Ok(());
        }

        let mut formatter = NasmFormatter::new();

        /* print the instructions */
        formatter.options_mut().set_digit_separator("`");
        formatter.options_mut().set_first_operand_char_index(5);

        let mut output = String::new();

        for instruction in &self.instructions {
            output.push(' ');
            formatter.format(&instruction, &mut output);
            output.push_str(" ;");
        }

        write!(
            f,
            "0x{:x}:{}",
            self.instructions.last().unwrap().ip(),
            output
        )
    }
}
