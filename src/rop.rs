use crate::gadget::{self, Gadget};
use iced_x86::*;

#[derive(PartialEq)]
pub enum RopElementKind {
    ImmediateValue,
    Gadget,
}
pub struct RopElement {
    value: u64,
    element_type: RopElementKind,
}

impl RopElement {
    pub fn new(value: u64, element_type: RopElementKind) -> Self {
        RopElement {
            value: value,
            element_type: element_type,
        }
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn kind(&self) -> &RopElementKind {
        &self.element_type
    }
}

impl std::fmt::Display for RopElement {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "0x{:x}", self.value)
    }
}

pub fn find_write_what_where(gadgets: &Vec<Gadget>) -> Result<Vec<Gadget>, &'static str> {
    let mut www_gadgets: Vec<Gadget> = Vec::new();

    for gadget in gadgets {
        let instruction = gadget.instructions[1];

        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Memory
            && instruction.op1_kind() == OpKind::Register
            && instruction.memory_displacement64() == 0
        {
            www_gadgets.push(gadget.clone());
        }
    }

    if www_gadgets.len() == 0 {
        return Err("Cannot find write what where gadget");
    }

    Ok(www_gadgets)
}

pub fn pop(
    gadgets: &Vec<Gadget>,
    register: Register,
    value: u64,
) -> Result<Vec<RopElement>, &'static str> {
    for g in gadgets {
        for i in (1..g.instructions.len()) {
            let instruction = g.instructions[i];

            if instruction.mnemonic() != Mnemonic::Pop {
                break;
            }

            if instruction.op0_register() == register {
                let mut v: Vec<RopElement> = Vec::new();

                v.push(RopElement::new(instruction.ip(), RopElementKind::Gadget));
                v.push(RopElement::new(value, RopElementKind::ImmediateValue));

                for j in (0..i - 1) {
                    v.push(RopElement::new(0, RopElementKind::ImmediateValue));
                }

                return Ok(v);
            }
        }
    }

    Err("Cannot find pop")
}

pub fn binsh(
    gadgets: &Vec<Gadget>,
    writable_address: u64,
) -> Result<Vec<RopElement>, &'static str> {
    let mut ropchain: Vec<RopElement> = Vec::new();

    if gadgets.len() == 0 {
        return Err("Not enough gadgets to generate ropchain.");
    }

    let www_gadgets = find_write_what_where(gadgets);

    let www_gadgets = match www_gadgets {
        Ok(gadget) => gadget,
        Err(e) => return Err(e),
    };

    /* First we need to find write what where gadget */

    Ok(ropchain)
}
