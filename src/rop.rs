use std::vec;

use crate::gadget::Gadget;
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
            && instruction.memory_segment() == Register::DS
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
        for i in 1..g.instructions.len() {
            let instruction = g.instructions[i];

            if instruction.mnemonic() != Mnemonic::Pop {
                break;
            }

            if instruction.op0_register() == register {
                let mut v: Vec<RopElement> = Vec::new();

                v.push(RopElement::new(instruction.ip(), RopElementKind::Gadget));

                for _ in 0..i - 1 {
                    v.push(RopElement::new(0, RopElementKind::ImmediateValue));
                }

                v.push(RopElement::new(value, RopElementKind::ImmediateValue));

                return Ok(v);
            }
        }
    }

    Err("Cannot find pop")
}

pub fn write_data(
    gadgets: &Vec<Gadget>,
    data: &Vec<u64>,
    address: u64,
) -> Result<Vec<RopElement>, &'static str> {
    let www_gadgets = find_write_what_where(&gadgets);

    let www_gadgets = match www_gadgets {
        Ok(g) => g,
        Err(e) => return Err(e),
    };

    /* try to find a usable one */
    for g in www_gadgets {
        let reg_src = g.instructions[1].op1_register();
        let reg_dst = g.instructions[1].memory_base();

        let mut rop: Vec<RopElement> = Vec::new();

        for i in 0..data.len() {
            /* Reg src contains the data we want to write */
            let mut pop_reg_src = match pop(gadgets, reg_src, data[i]) {
                Ok(p) => p,
                Err(_) => continue,
            };

            /* reg dst contains the destination address */
            let mut pop_reg_dst = match pop(gadgets, reg_dst, address + i as u64 * 8) {
                Ok(p) => p,
                Err(_) => continue,
            };

            rop.append(&mut pop_reg_src);
            rop.append(&mut pop_reg_dst);
            rop.push(RopElement::new(
                g.instructions[1].ip(),
                RopElementKind::Gadget,
            ));
        }

        if rop.len() != 0 {
            return Ok(rop);
        }
    }

    Err("Impossible to find the gadgets needed to write bytes")
}

/* 2f62696e2f7368 */
const BINSH_STR: u64 = 0x68732F6E69622F;

pub fn binsh(
    gadgets: &Vec<Gadget>,
    writable_address: u64,
) -> Result<Vec<RopElement>, &'static str> {
    let mut ropchain: Vec<RopElement> = Vec::new();

    if gadgets.len() == 0 {
        return Err("Not enough gadgets to generate ropchain.");
    }

    let mut w = match write_data(gadgets, &vec![BINSH_STR], writable_address) {
        Ok(r) => r,
        Err(e) => return Err(e),
    };

    ropchain.append(&mut w);

    Ok(ropchain)
}
