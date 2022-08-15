use crate::rop::RopElement;

pub fn pwntool(binary_name: &String, rop: &Vec<RopElement>)
{
    println!("# Code generated by Rrop for python3");
    println!("from pwn import *\n");
    println!("OFFSET_SAVED_RIP=0 # To change with the offset your found\n\n");

    println!("payload = b\"\\x90\" * OFFSET_SAVED_RIP");
    for element in rop
    {
        println!("payload += p64(0x{:x}) # {}", element.value(), element.gadget());
    }

    println!("\nio = process(\"./{}\")", binary_name);
    println!("io.send(payload)");
    println!("io.interactive()");
}