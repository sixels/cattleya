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

pub struct Elf32Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u32,
    pub e_phoff: u32,
    pub e_shoff: u32,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl ElfHeader {
    pub fn from_elf32(header: &Elf32Header) -> Self {
        Self {
            e_ident: header.e_ident,
            e_type: header.e_type,
            e_machine: header.e_machine,
            e_version: header.e_version,
            e_entry: header.e_entry as u64,
            e_phoff: header.e_phoff as u64,
            e_shoff: header.e_shoff as u64,
            e_flags: header.e_flags,
            e_ehsize: header.e_ehsize,
            e_phentsize: header.e_phentsize,
            e_phnum: header.e_phnum,
            e_shentsize: header.e_shentsize,
            e_shnum: header.e_shnum,
            e_shstrndx: header.e_shstrndx,
        }
    }
}

pub fn is_elf(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0..4] == HEADER_MAGIC
}
