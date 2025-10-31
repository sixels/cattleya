mod error;
mod obfus;
mod util;

pub use error::{Error, Result};
pub use obfus::Obfuscator;

pub struct ObfuscateBuilder<'a> {
    input: &'a mut Vec<u8>,
    class: bool,
    endian: bool,
    sechdr: bool,
    symbol: bool,
    comment: bool,
    section: Option<String>,
    got: bool,
    got_l: Option<String>,
    got_f: Option<String>,
    encrypt: bool,
    encrypt_f: Option<String>,
    encrypt_key: Option<String>,
}

impl<'a> ObfuscateBuilder<'a> {
    pub fn new(input: &'a mut Vec<u8>) -> Self {
        Self {
            input,
            class: false,
            endian: false,
            sechdr: false,
            symbol: false,
            comment: false,
            section: None,
            got: false,
            got_l: None,
            got_f: None,
            encrypt: false,
            encrypt_f: None,
            encrypt_key: None,
        }
    }
}

impl<'a> ObfuscateBuilder<'a> {
    pub fn class(mut self, enable: bool) -> Self {
        self.class = enable;
        self
    }
    pub fn endian(mut self, enable: bool) -> Self {
        self.endian = enable;
        self
    }
    pub fn nullify_section_headers(mut self, enable: bool) -> Self {
        self.sechdr = enable;
        self
    }
    pub fn nullify_symbols(mut self, enable: bool) -> Self {
        self.symbol = enable;
        self
    }
    pub fn nullify_comment(mut self, enable: bool) -> Self {
        self.comment = enable;
        self
    }
    pub fn nullify_section(mut self, name: impl Into<String>) -> Self {
        self.section = Some(name.into());
        self
    }

    pub fn got_overwrite(
        mut self,
        target_lib_func: impl Into<String>,
        new_func: impl Into<String>,
    ) -> Self {
        self.got = true;
        self.got_l = Some(target_lib_func.into());
        self.got_f = Some(new_func.into());
        self
    }

    pub fn encrypt_function_name(
        mut self,
        func: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        self.encrypt = true;
        self.encrypt_f = Some(func.into());
        self.encrypt_key = Some(key.into());
        self
    }

    pub fn obfuscate_in_place(&mut self) -> Result<()> {
        self.exec_obfus()
    }

    pub fn bytes(&self) -> &[u8] {
        self.input.as_slice()
    }
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        self.input.as_mut_slice()
    }

    fn exec_obfus(&mut self) -> Result<()> {
        // Use in-memory obfuscator, no filesystem interaction.
        let mut out = self.input.clone();
        let mut obfuscator =
            crate::obfus::ObfuscatorMem::from_bytes(self.input.as_slice(), out.as_mut_slice())?;

        if self.class {
            let _ = obfuscator.change_class();
        }
        if self.endian {
            let _ = obfuscator.change_endian();
        }
        if self.sechdr {
            let _ = obfuscator.nullify_sec_hdr();
        }
        if self.symbol {
            let _ = obfuscator.nullify_section(".strtab");
        }
        if self.comment {
            let _ = obfuscator.nullify_section(".comment");
        }
        if let Some(section) = &self.section {
            let _ = obfuscator.nullify_section(section);
        }
        if self.got {
            let got_l = self.got_l.as_deref().ok_or(Error::InvalidOption(
                "both library and function names are required",
            ))?;
            let got_f = self.got_f.as_deref().ok_or(Error::InvalidOption(
                "both library and function names are required",
            ))?;
            let _ = obfuscator.got_overwrite(got_l, got_f);
        }
        // if self.encrypt {
        //     let func = self.encrypt_f.as_deref().ok_or(Error::InvalidOption(
        //         "target function name and encryption key is required",
        //     ))?;
        //     let key = self.encrypt_key.as_deref().ok_or(Error::InvalidOption(
        //         "target function name and encryption key is required",
        //     ))?;
        //     let _ = obfuscator.encrypt_function_name(func, key);
        // }

        // Write back to caller's buffer
        *self.input = out;
        Ok(())
    }
}
