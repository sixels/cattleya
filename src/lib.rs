mod elf;
mod error;
mod obfus;

pub use error::{Error, Result};

use crate::obfus::ObfuscatorMem;

pub struct ElfObfuscator {
    class: bool,
    endian: bool,
    sechdr: bool,
    symbol: bool,
    comment: bool,
    section: Option<String>,
    got: Option<ElfObfuscationGotOverwrite>,
    encrypt: Option<ElfObfuscationEncryptFunction>,
}

struct ElfObfuscationEncryptFunction {
    func: String,
    key: String,
}

struct ElfObfuscationGotOverwrite {
    lib_func: String,
    new_func: String,
}

impl ElfObfuscator {
    pub fn new() -> Self {
        Self {
            class: false,
            endian: false,
            sechdr: false,
            symbol: false,
            comment: false,
            section: None,
            got: None,
            encrypt: None,
        }
    }
}

impl ElfObfuscator {
    /// Change architecture class in the ELF
    pub fn swap_class(mut self) -> Self {
        self.class = true;
        self
    }
    /// Change endian in the ELF
    pub fn swap_endian(mut self) -> Self {
        self.endian = true;
        self
    }
    /// Nullify section header in the ELF
    pub fn nullify_section_headers(mut self) -> Self {
        self.sechdr = true;
        self
    }
    /// Nullify symbols in the ELF
    pub fn nullify_symbols(mut self) -> Self {
        self.symbol = true;
        self
    }
    /// Nullify comment section in the ELF
    pub fn nullify_comment(mut self) -> Self {
        self.comment = true;
        self
    }
    /// Nullify section in the ELF
    pub fn nullify_section(mut self, name: impl Into<String>) -> Self {
        self.section = Some(name.into());
        self
    }

    /// Perform GOT overwrite
    pub fn got_overwrite(
        mut self,
        target_lib_func: impl Into<String>,
        new_func: impl Into<String>,
    ) -> Self {
        self.got = Some(ElfObfuscationGotOverwrite {
            lib_func: target_lib_func.into(),
            new_func: new_func.into(),
        });
        self
    }

    /// Encrypt function name with the given key
    pub fn encrypt_function_name(
        mut self,
        func: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        self.encrypt = Some(ElfObfuscationEncryptFunction {
            func: func.into(),
            key: key.into(),
        });
        self
    }

    /// Obfuscate the ELF
    pub fn obfuscate<'a>(self, input: &'a mut [u8]) -> Result<()> {
        let mut obfuscator = ObfuscatorMem::new(input)?;

        if self.class {
            obfuscator.change_class()?;
        }
        if self.endian {
            obfuscator.change_endian()?;
        }
        if self.sechdr {
            obfuscator.nullify_sec_hdr()?;
        }
        if self.symbol {
            obfuscator.nullify_section(".strtab")?;
        }
        if self.comment {
            obfuscator.nullify_section(".comment")?;
        }
        if let Some(section) = &self.section {
            obfuscator.nullify_section(section)?;
        }
        if let Some(got) = &self.got {
            obfuscator.got_overwrite(&got.lib_func, &got.new_func)?;
        }
        if let Some(encrypt) = &self.encrypt {
            if !obfuscator.encrypt_function_name(&encrypt.func, &encrypt.key)? {
                return Err(Error::FunctionNotFound);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SAMPLE_ELF: &str = "/bin/cat";

    #[test]
    fn test_class_swap() {
        let mut input: Vec<u8> = std::fs::read(SAMPLE_ELF).unwrap();
        let original_class = input[elf::EI_CLASS];

        ElfObfuscator::new()
            .swap_class()
            .obfuscate(&mut input)
            .unwrap();

        assert_ne!(input[elf::EI_CLASS], original_class);
    }

    #[test]
    fn test_endian_swap() {
        let mut input: Vec<u8> = std::fs::read(SAMPLE_ELF).unwrap();
        let original_endian = input[elf::EI_DATA];

        ElfObfuscator::new()
            .swap_endian()
            .obfuscate(&mut input)
            .unwrap();

        assert_ne!(input[elf::EI_DATA], original_endian);
    }

    #[test]
    fn test_nullify_section_headers() {
        let mut input: Vec<u8> = std::fs::read(SAMPLE_ELF).unwrap();

        ElfObfuscator::new()
            .nullify_section_headers()
            .obfuscate(&mut input)
            .unwrap();

        let section_headers = goblin::elf::Elf::parse(&input).unwrap().section_headers;
        let section_headers_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                section_headers.as_ptr() as *const u8,
                section_headers.len() * std::mem::size_of::<goblin::elf::SectionHeader>(),
            )
        };

        assert_eq!(&section_headers_bytes[..0x8c], [0; 0x8c]);
    }

    #[test]
    fn test_nullify_symbols() {
        let mut input: Vec<u8> = std::fs::read(SAMPLE_ELF).unwrap();

        let result = ElfObfuscator::new().nullify_symbols().obfuscate(&mut input);
        match result {
            Ok(_) => (),
            Err(Error::InvalidOption(..)) => {
                eprintln!("\nWARN: .strtab section not found\n");
                return;
            }
            Err(err) => panic!("{}", err),
        }

        let elf = goblin::elf::Elf::parse(&input).unwrap();

        // get some entry from strtab section
        if let Some(entry) = elf.strtab.get_at(1) {
            assert!(entry.is_empty());
        } else {
            eprintln!("\nWARN: .strtab section not found\n");
        }
    }

    #[test]
    fn test_nullify_comment() {
        let mut input: Vec<u8> = std::fs::read(SAMPLE_ELF).unwrap();

        let result = ElfObfuscator::new().nullify_comment().obfuscate(&mut input);
        match result {
            Ok(_) => (),
            Err(Error::InvalidOption(..)) => {
                eprintln!("\nWARN: .comment section not found\n");
                return;
            }
            Err(err) => panic!("{}", err),
        }

        let elf = goblin::elf::Elf::parse(&input).unwrap();

        let comment_section = elf.section_headers.iter().find(|section| {
            elf.shdr_strtab
                .get_at(section.sh_name as usize)
                .is_some_and(|s| s == ".comment")
        });

        if let Some(comment_section) = comment_section {
            let comment_section_addr = comment_section.sh_offset as usize;
            let comment_section_size = comment_section.sh_size as usize;
            let comment_section_bytes =
                &input[comment_section_addr..comment_section_addr + comment_section_size];
            assert_eq!(&comment_section_bytes[..], [0; 0x1b]);
        } else {
            eprintln!("\nWARN: .comment section not found\n");
        }
    }

    #[test]
    fn test_nullify_comment_section_manually() {
        let mut input: Vec<u8> = std::fs::read(SAMPLE_ELF).unwrap();

        let result = ElfObfuscator::new()
            .nullify_section(".comment")
            .obfuscate(&mut input);
        match result {
            Ok(_) => (),
            Err(Error::InvalidOption(..)) => {
                eprintln!("\nWARN: .comment section not found\n");
                return;
            }
            Err(err) => panic!("{}", err),
        }

        let elf = goblin::elf::Elf::parse(&input).unwrap();

        let comment_section = elf.section_headers.iter().find(|section| {
            elf.shdr_strtab
                .get_at(section.sh_name as usize)
                .is_some_and(|s| s == ".comment")
        });

        if let Some(comment_section) = comment_section {
            let comment_section_addr = comment_section.sh_offset as usize;
            let comment_section_size = comment_section.sh_size as usize;
            let comment_section_bytes =
                &input[comment_section_addr..comment_section_addr + comment_section_size];
            assert_eq!(&comment_section_bytes[..], [0; 0x1b]);
        } else {
            eprintln!("\nWARN: .comment section not found\n");
        }
    }

    #[ignore = "Symbol lookup is broken in the current implementation"]
    #[test]
    fn test_encrypt_function_name() {
        let mut input: Vec<u8> = std::fs::read(SAMPLE_ELF).unwrap();

        let result = ElfObfuscator::new()
            .encrypt_function_name("__libc_start_main", "main")
            .obfuscate(&mut input);
        match result {
            Ok(_) => (),
            Err(Error::InvalidOption(..)) => {
                eprintln!("\nWARN: .comment section not found\n");
                return;
            }

            Err(Error::FunctionNotFound) => panic!("function not found"),
            Err(err) => panic!("{}", err),
        }

        let elf = goblin::elf::Elf::parse(&input).unwrap();

        for sym in elf.dynsyms.iter() {
            let name = elf.dynstrtab.get_at(sym.st_name as usize).unwrap();
            if name.starts_with("__libc_start_main") {
                println!("{}", name);
            }
        }
    }
}
