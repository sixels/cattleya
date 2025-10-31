pub const HEADER_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

pub use constants::*;

#[allow(dead_code)]
mod constants {
    pub const EI_CLASS: usize = 4;
    pub const EI_DATA: usize = 5;
    pub const ELFCLASS32: u8 = 1;
    pub const ELFCLASS64: u8 = 2;
}

#[repr(C, packed)]
#[derive(Debug)]
pub struct ElfHeader {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

pub fn is_elf(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0..4] == HEADER_MAGIC
}
