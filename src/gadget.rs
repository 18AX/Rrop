use iced_x86::*;

struct Gadget {
    instructions: Vec<Instruction>,
}

impl std::fmt::Display for Gadget {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.instructions.len() < 1 {
            return Ok(());
        }

        let mut formatter = NasmFormatter::new();

        /* print the instructions */
        formatter.options_mut().set_digit_separator("`");
        formatter.options_mut().set_first_operand_char_index(10);

        let mut output = String::new();

        for instruction in &self.instructions {
            output.push(' ');
            formatter.format(&instruction, &mut output);
            output.push_str(" ;");
        }

        write!(f, "{:x}:{}", self.instructions[0].ip(), output)
    }
}
