use goblin::pe::PE;
use std::{fs};
use capstone::arch::x86::ArchMode;
use capstone::prelude::BuildsCapstone;

const INTERESTING_FUNCTION_NAMES: &[&str] = &[
    "NtOpenProcess",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateThreadEx",
    "NtWaitForSingleObject",
    "NtFreeVirtualMemory",
    "NtClose",
    "GetSyscallNumber"
];

fn main() {
    let buffer = fs::read("ntdll.dll")
        .expect("failed to read dll");

    let pe = PE::parse(&buffer)
        .expect("failed to parse dll");

    let mut sorted_exports: Vec<_> = pe.exports.iter().collect();
    sorted_exports.sort_by_key(|export| export.offset);

    let target_exports = pe.exports.iter()
        .filter(|&x| x.name.is_some() && INTERESTING_FUNCTION_NAMES.contains(&x.name.unwrap()))
        .collect::<Vec<_>>();

    let cs = capstone::Capstone::new()
        .x86()
        .mode(ArchMode::Mode64)
        .build().expect("failed to compile capstone");

    for func in target_exports {
        let (index, _) = sorted_exports.iter().enumerate().find(|(_, x)| {
            x.name == func.name && x.offset == func.offset // TODO un-ew this
        }).expect(format!("could not find {:?} in sorted_exports", func).as_str());
        let next_export = sorted_exports[index+2]; // +2 if using wine .dlls - TODO make sure index exists before accessing

        let start = func.rva;      // TODO : do this safely!!
        let end = next_export.rva; // TODO : do this safely!!

        let raw_instructions = cs.disasm_all(
            buffer[start..end].iter().as_slice(),
            func.rva as u64
        ).expect("failed to disassemble");


        println!("assembly code for function {:?}", func);
        for insn in raw_instructions.iter() {
            println!(
                "0x{:x}: {:<6} {}",
                insn.address(),
                insn.mnemonic().unwrap_or(""),
                insn.op_str().unwrap_or("")
            );
        }
    }
}
