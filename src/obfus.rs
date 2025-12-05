use crate::elf::{self, ElfHeader};
use regex::Regex;

pub struct ObfuscatorMem<'a> {
    buffer: &'a mut [u8],
    elf_hdr: ElfHeader,
    sec_hdr: String,
    sec_table: u64,
    dyn_strings: String,
    string_table: String,
}

impl<'a> ObfuscatorMem<'a> {
    pub fn new(input: &'a mut [u8]) -> crate::error::Result<Self> {
        if !elf::is_elf(input) {
            return Err(crate::error::Error::InvalidMagic);
        }

        let arch = input[elf::EI_CLASS];
        if arch != elf::ELFCLASS32 && arch != elf::ELFCLASS64 {
            return Err(crate::error::Error::InvalidArch(arch));
        }

        let is_64 = arch == elf::ELFCLASS64;

        // Parsing the Header
        let elf_hdr: ElfHeader = if is_64 {
            unsafe { std::ptr::read(input.as_ptr() as *const ElfHeader) }
        } else {
            let elf32_hdr: elf::Elf32Header =
                unsafe { std::ptr::read(input.as_ptr() as *const elf::Elf32Header) };
            ElfHeader::from_elf32(&elf32_hdr)
        };

        // Determine Section Header Table Offset (e_shoff)
        let sec_table = if is_64 {
            u64::from_le_bytes(input[40..48].try_into().unwrap())
        } else {
            u32::from_le_bytes(input[32..36].try_into().unwrap()) as u64
        };

        // 64-bit e_shstrndx is at 0x3E, 32-bit is at 0x32. The struct abstraction handles this.
        let sh_str_ndx = elf_hdr.e_shstrndx as u64;

        // Calculate address of the Section Header for the String Table
        let sh_table_header_addr = (sec_table + (sh_str_ndx * elf_hdr.e_shentsize as u64)) as usize;
        let sh_table_header =
            &input[sh_table_header_addr..sh_table_header_addr + elf_hdr.e_shentsize as usize];

        // 64-bit: sh_offset is at 0x18 (24), size 8
        // 32-bit: sh_offset is at 0x10 (16), size 4
        let sh_table_addr = if is_64 {
            u64::from_le_bytes(sh_table_header[24..32].try_into().unwrap()) as usize
        } else {
            u32::from_le_bytes(sh_table_header[16..20].try_into().unwrap()) as usize
        };

        // Locate the end of the strings (scan for null bytes manually?)
        let mut curr_strings = -1;
        let mut index = sh_table_addr;
        let mut curr_byte;

        // Safety check to prevent OOB if file is malformed
        while index < input.len() && curr_strings < elf_hdr.e_shnum as isize {
            curr_byte = input[index] as isize;
            if curr_byte == 0 {
                curr_strings += 1;
            }
            index += 1;
        }

        let mut data_copy: Vec<u8> = vec![0; index - sh_table_addr];
        data_copy.copy_from_slice(&input[sh_table_addr..index]);
        for b in &mut data_copy {
            if *b == 0 {
                *b = b' ';
            }
        }
        let sec_hdr = String::from_utf8_lossy(&data_copy).to_string();

        let mut obfus = ObfuscatorMem {
            buffer: input,
            elf_hdr,
            sec_hdr,
            sec_table,
            dyn_strings: String::new(),
            string_table: String::new(),
        };

        // Load .dynstr
        if let Ok((section_addr, section_size, _, _)) = obfus.get_section(".dynstr") {
            obfus.dyn_strings =
                String::from_utf8_lossy(&obfus.buffer[section_addr..section_addr + section_size])
                    .to_string();
        }

        // Load .strtab
        let (section_addr, section_size, _, _) =
            obfus.get_section(".strtab").unwrap_or((0, 0, 0, 0));
        if section_addr != 0 && section_size != 0 {
            obfus.string_table =
                String::from_utf8_lossy(&obfus.buffer[section_addr..section_addr + section_size])
                    .to_string();
        }
        Ok(obfus)
    }

    fn is_64bit(&self) -> bool {
        self.buffer[elf::EI_CLASS] == elf::ELFCLASS64
    }
    fn is_enable_pie(&self) -> bool {
        self.buffer[16] != 2
    }
    fn is_stripped(&self) -> bool {
        self.get_section(".symtab").is_err()
    }

    fn v2p(&self, virtual_addr: usize, section: &str) -> usize {
        let (section_addr, _, _, vaddr) = self.get_section(section).unwrap();
        section_addr + virtual_addr - vaddr
    }

    fn get_section(&self, section: &str) -> crate::error::Result<(usize, usize, usize, usize)> {
        let searched_idx = self.sec_hdr.find(section).unwrap_or(usize::MAX);
        if searched_idx == usize::MAX {
            return Err(crate::error::Error::SectionNotFound(section.to_owned()));
        }
        for i in 0..self.elf_hdr.e_shnum as u64 {
            let offset = (self.sec_table + i * self.elf_hdr.e_shentsize as u64) as usize;
            let sec_hdr = &self.buffer[offset..offset + self.elf_hdr.e_shentsize as usize];

            let string_offset = u32::from_le_bytes(sec_hdr[0..4].try_into().unwrap());
            if string_offset == searched_idx as u32 {
                if self.is_64bit() {
                    return Ok((
                        u64::from_le_bytes(sec_hdr[24..32].try_into().unwrap()) as usize, // sh_offset
                        u64::from_le_bytes(sec_hdr[32..40].try_into().unwrap()) as usize, // sh_size
                        u64::from_le_bytes(sec_hdr[56..64].try_into().unwrap()) as usize, // sh_entsize
                        u64::from_le_bytes(sec_hdr[16..24].try_into().unwrap()) as usize, // sh_addr
                    ));
                } else {
                    return Ok((
                        u32::from_le_bytes(sec_hdr[16..20].try_into().unwrap()) as usize, // sh_offset
                        u32::from_le_bytes(sec_hdr[20..24].try_into().unwrap()) as usize, // sh_size
                        u32::from_le_bytes(sec_hdr[36..40].try_into().unwrap()) as usize, // sh_entsize
                        u32::from_le_bytes(sec_hdr[12..16].try_into().unwrap()) as usize, // sh_addr
                    ));
                }
            }
        }
        Err(crate::error::Error::SectionNotFound(section.to_owned()))
    }

    pub fn change_class(&mut self) -> crate::error::Result<()> {
        self.buffer[elf::EI_CLASS] = 3 - self.buffer[elf::EI_CLASS];
        Ok(())
    }
    pub fn change_endian(&mut self) -> crate::error::Result<()> {
        self.buffer[elf::EI_DATA] = 3 - self.buffer[elf::EI_DATA];
        Ok(())
    }
    pub fn nullify_sec_hdr(&mut self) -> crate::error::Result<()> {
        for i in 0..self.elf_hdr.e_shnum as u64 {
            let offset = self.elf_hdr.e_shoff + i * self.elf_hdr.e_shentsize as u64;
            self.buffer[offset as usize..(offset + self.elf_hdr.e_shentsize as u64) as usize]
                .fill(0);
        }
        Ok(())
    }
    pub fn nullify_section(&mut self, section: &str) -> crate::error::Result<()> {
        let (section_addr, section_size, _, _) = self.get_section(section)?;
        self.buffer[section_addr..section_addr + section_size].fill(0);
        Ok(())
    }
    fn get_dyn_func_idx(&self, function: &str) -> crate::error::Result<u64> {
        let idx = self.dyn_strings.find(function).unwrap();
        let (section_addr, section_size, entry_size, _) = self.get_section(".dynsym").unwrap();
        let dynsym_section = &self.buffer[section_addr..section_addr + section_size];
        for i in 0..section_size / entry_size {
            let entry = &dynsym_section[i * entry_size..(i + 1) * entry_size];
            let name_offset = u32::from_le_bytes(entry[0..4].try_into().unwrap());
            if name_offset == idx as u32 {
                return Ok(i as u64);
            }
        }
        Err(crate::error::Error::NotFound(
            "function not found".to_owned() + function,
        ))
    }
    fn get_func_addr_by_name(&self, function: &str) -> crate::error::Result<u64> {
        let idx = self.string_table.find(function).unwrap();
        let (section_addr, section_size, entry_size, _) = self.get_section(".symtab").unwrap();
        let dynsym_section = &self.buffer[section_addr..section_addr + section_size];
        for i in 0..section_size / entry_size {
            let entry = &dynsym_section[i * entry_size..(i + 1) * entry_size];
            if self.is_64bit() {
                if u32::from_le_bytes(entry[0..4].try_into().unwrap()) == idx as u32 {
                    return Ok(u64::from_le_bytes(entry[8..16].try_into().unwrap()));
                }
            } else if u32::from_le_bytes(entry[0..4].try_into().unwrap()) == idx as u32 {
                return Ok(u32::from_le_bytes(entry[4..8].try_into().unwrap()) as u64);
            }
        }
        Err(crate::error::Error::NotFound(
            "function not found".to_owned() + function,
        ))
    }

    pub fn got_overwrite(
        &mut self,
        target_function_name: &str,
        new_func_name: &str,
    ) -> crate::error::Result<()> {
        if self.is_enable_pie() {
            return Err(crate::error::Error::InvalidOption(
                "replacing GOT get will no effect with PIE enabled",
            ));
        } else if self.is_stripped() {
            return Err(crate::error::Error::InvalidOption(
                "cannot overwrite GOT with stripped binary",
            ));
        }
        let dyn_func = self.get_dyn_func_idx(target_function_name)?;

        if self.is_64bit() {
            let (section_addr, section_size, entry_size, _) =
                self.get_section(".rela.plt").unwrap();

            for i in 0..section_size / entry_size {
                let entry = &self.buffer[section_addr..section_addr + section_size]
                    [i * entry_size..(i + 1) * entry_size];

                // Elf64_Rela: r_offset(8) + r_info(8) + r_addend(8)
                if u64::from_le_bytes(entry[8..16].try_into().unwrap()) >> 32 == dyn_func {
                    let offset = u64::from_le_bytes(entry[0..8].try_into().unwrap());
                    let addr = self.v2p(offset as usize, ".got.plt");
                    let new_func_addr = self.get_func_addr_by_name(new_func_name)?;
                    self.buffer[addr..addr + 8].copy_from_slice(&new_func_addr.to_le_bytes());
                    return Ok(());
                }
            }
        } else {
            let (section_addr, section_size, entry_size, _) = self.get_section(".rel.plt").unwrap();

            for i in 0..section_size / entry_size {
                let entry = &self.buffer[section_addr..section_addr + section_size]
                    [i * entry_size..(i + 1) * entry_size];

                // Elf32_Rel: r_offset(4) + r_info(4)
                // The info is at offset 4
                let r_info = u32::from_le_bytes(entry[4..8].try_into().unwrap());

                if (r_info >> 8) as u64 == dyn_func {
                    let offset = u32::from_le_bytes(entry[0..4].try_into().unwrap());
                    let addr = self.v2p(offset as usize, ".got.plt");
                    let new_func_addr = self.get_func_addr_by_name(new_func_name)?;
                    // Write 4 bytes for 32-bit address
                    self.buffer[addr..addr + 4]
                        .copy_from_slice(&(new_func_addr as u32).to_le_bytes());
                    return Ok(());
                }
            }
        }
        Err(crate::error::Error::Obfuscation("failed to overwrite GOT"))
    }

    pub fn encrypt_function_name(
        &mut self,
        function: &str,
        key: &str,
    ) -> crate::error::Result<bool> {
        use sha2::digest::Digest;
        use std::io::Write;

        let hash = sha2::Sha256::digest(key.as_bytes());
        let encryptor = crypto::aessafe::AesSafe256Encryptor::new(&hash);

        let mut encrypted_function_name = Vec::new();
        aesstream::AesWriter::new(&mut encrypted_function_name, encryptor)
            .map_err(crate::error::Error::OpenFile)?
            .write_all(function.as_bytes())
            .map_err(crate::error::Error::Io)?;

        let Some(idx) = self.string_table.find(function) else {
            return Ok(false);
        };
        let (section_addr, _, _, _) = self.get_section(".strtab").unwrap();

        if function.len() > encrypted_function_name.len() {
            let mut tmp = vec![0; function.len() - encrypted_function_name.len()];
            encrypted_function_name.append(&mut tmp);
        } else {
            encrypted_function_name = encrypted_function_name[0..function.len()].to_vec();
        }

        self.buffer[section_addr + idx..section_addr + idx + function.len()]
            .copy_from_slice(&encrypted_function_name);

        Ok(true)
    }

    pub fn erase_section_strings<I>(
        &mut self,
        section: &str,
        patterns: I,
    ) -> crate::error::Result<()>
    where
        I: IntoIterator<Item = Regex>,
    {
        let (section_addr, section_size, _, _) = self.get_section(section)?;
        let mut data_copy: Vec<u8> = vec![0; section_size];
        data_copy.copy_from_slice(&self.buffer[section_addr..section_addr + section_size]);

        let patterns = patterns.into_iter().collect::<Vec<_>>();
        let mut start = 0;
        while start < section_size {
            let mut cursor = start;
            while cursor < section_size && data_copy[cursor] != 0 {
                cursor += 1;
            }

            if cursor < section_size
                && let Ok(string) = std::str::from_utf8(&data_copy[start..cursor])
                && !string.is_empty()
            {
                for pattern in &patterns {
                    if let Some(match_) = pattern.find(string) {
                        let match_start = start + match_.start();
                        let match_end = start + match_.end();

                        data_copy[match_start..match_end].fill(b' ');
                        break;
                    }
                }
            }
            start = cursor + 1;
        }

        self.buffer[section_addr..section_addr + section_size].copy_from_slice(&data_copy);
        Ok(())
    }
}
