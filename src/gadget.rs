use iced_x86::*;

#[derive(Clone)]
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

fn build_gadget(instructions: &Vec<Instruction>, position: usize) -> Result<Vec<Gadget>, String> {
    let mut res: Vec<Gadget> = Vec::new();

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

        /* pop r15 encoded is 415F, pop rdi encoded is 5F so a pop r15 can also be a pop rdi */
        if mnem == Mnemonic::Pop && instructions[i].op0_register() == Register::R15 {
            let mut rdi_gadget = Gadget {
                instructions: gadget.instructions.clone(),
            };

            let mut ins = Instruction::new();
            ins.set_code(Code::Pop_r64);
            ins.set_op0_register(Register::RDI);
            ins.set_ip(instructions[i].ip() + 8);
            rdi_gadget.instructions.push(ins);

            res.push(rdi_gadget);
        }

        gadget.instructions.push(instructions[i].clone());
    }

    if gadget.instructions.len() > 1 {
        res.push(gadget);
    }

    if res.len() == 0 {
        return Err(String::from("Cannot build a valid gadget"));
    }

    Ok(res)
}

pub fn find_gadgets(instructions: &Vec<Instruction>) -> Vec<Gadget> {
    let mut gadgets: Vec<Gadget> = Vec::new();

    for i in 0..instructions.len() {
        if instructions[i].mnemonic() == Mnemonic::Ret
            || instructions[i].mnemonic() == Mnemonic::Retf
        {
            match build_gadget(instructions, i).as_mut() {
                Ok(e) => gadgets.append(e),
                Err(_) => continue,
            };
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
