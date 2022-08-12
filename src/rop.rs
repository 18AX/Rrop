use crate::gadget::{self, Gadget};
use iced_x86::*;

#[derive(PartialEq)]
pub enum RopElementKind {
    ImmediateValue,
    Gadget,
}
pub struct RopElement {
    immediate_value: u64,
    gadget: Gadget,
    element_type: RopElementKind,
}

impl RopElement {
    pub fn from_immediate(immediate: u64) -> Self {
        RopElement {
            immediate_value: immediate,
            gadget: Gadget::default(),
            element_type: RopElementKind::ImmediateValue,
        }
    }

    pub fn from_gadget(gadget: Gadget) -> Self {
        RopElement {
            immediate_value: 0,
            gadget: gadget,
            element_type: RopElementKind::Gadget,
        }
    }

    pub fn get_immediate(&self) -> u64 {
        self.immediate_value
    }

    pub fn get_gadget(&self) -> &Gadget {
        &self.gadget
    }

    pub fn get_type(&self) -> &RopElementKind {
        &self.element_type
    }
}

impl std::fmt::Display for RopElement {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.element_type == RopElementKind::Gadget {
            let g = &self.gadget;
            return write!(f, "{}", g);
        }

        write!(f, "{:x}", self.immediate_value)
    }
}

pub fn find_write_what_where(gadgets: Vec<Gadget>) -> Result<Vec<Gadget>, &'static str> {
    let mut www_gadgets: Vec<Gadget> = Vec::new();

    for gadget in gadgets {
        let instruction = gadget.instructions[1];

        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Memory
            && instruction.op1_kind() == OpKind::Register
            && instruction.memory_displacement64() == 0
        {
            www_gadgets.push(gadget);
        }
    }

    if www_gadgets.len() == 0 {
        return Err("Cannot find write what where gadget");
    }

    Ok(www_gadgets)
}

pub fn binsh(gadgets: Vec<Gadget>, writable_address: u64) -> Result<Vec<RopElement>, &'static str> {
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
