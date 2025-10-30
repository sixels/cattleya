mod error;
mod obfus;
mod util;
use std::io::Write as _;

pub use error::{Error, Result};
pub use obfus::Obfuscator;

pub struct ObfuscateBuilder {
    input: Option<String>,
    input_bytes: Option<Vec<u8>>,
    output: Option<String>,
    class: bool,
    endian: bool,
    sechdr: bool,
    symbol: bool,
    comment: bool,
    section: Option<String>,
    recursive: Option<String>,
    got: bool,
    got_l: Option<String>,
    got_f: Option<String>,
    encrypt: bool,
    encrypt_f: Option<String>,
    encrypt_key: Option<String>,
}

impl Default for ObfuscateBuilder {
    fn default() -> Self {
        Self {
            input: None,
            input_bytes: None,
            output: None,
            class: false,
            endian: false,
            sechdr: false,
            symbol: false,
            comment: false,
            section: None,
            recursive: None,
            got: false,
            got_l: None,
            got_f: None,
            encrypt: false,
            encrypt_f: None,
            encrypt_key: None,
        }
    }
}

impl ObfuscateBuilder {
    pub fn new() -> Self { Self::default() }

    pub fn input(mut self, path: impl Into<String>) -> Self { self.input = Some(path.into()); self }
    pub fn input_bytes(mut self, bytes: impl Into<Vec<u8>>) -> Self { self.input_bytes = Some(bytes.into()); self }
    pub fn output(mut self, path: impl Into<String>) -> Self { self.output = Some(path.into()); self }

    pub fn class(mut self, enable: bool) -> Self { self.class = enable; self }
    pub fn endian(mut self, enable: bool) -> Self { self.endian = enable; self }
    pub fn nullify_section_headers(mut self, enable: bool) -> Self { self.sechdr = enable; self }
    pub fn nullify_symbols(mut self, enable: bool) -> Self { self.symbol = enable; self }
    pub fn nullify_comment(mut self, enable: bool) -> Self { self.comment = enable; self }
    pub fn nullify_section(mut self, name: impl Into<String>) -> Self { self.section = Some(name.into()); self }

    pub fn recursive(mut self, dir: impl Into<String>) -> Self { self.recursive = Some(dir.into()); self }

    pub fn got_overwrite(mut self, target_lib_func: impl Into<String>, new_func: impl Into<String>) -> Self {
        self.got = true;
        self.got_l = Some(target_lib_func.into());
        self.got_f = Some(new_func.into());
        self
    }

    pub fn encrypt_function_name(mut self, func: impl Into<String>, key: impl Into<String>) -> Self {
        self.encrypt = true;
        self.encrypt_f = Some(func.into());
        self.encrypt_key = Some(key.into());
        self
    }

    pub fn obfuscate(self) -> Result<()> {
        if let Some(dir) = self.recursive.as_deref() {
            self.obfuscate_recursive(dir)
        } else {
            self.obfuscate_single()
        }
    }

    fn obfuscate_single(&self) -> Result<()> {
        let output_path = self.output.as_deref().unwrap_or("obfuscated");

        // If raw bytes provided, stage to a temporary file and clean it up after.
        if let Some(bytes) = self.input_bytes.as_ref() {
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let tmp_path = format!("/tmp/cattleya_input_{}_{}", pid, nanos);
            {
                let mut f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&tmp_path)
                    .map_err(error::Error::CreateFile)?;
                f.write_all(bytes).map_err(error::Error::Io)?;
            }
            let res = Self::exec_obfus(&tmp_path, output_path, self);
            // Best-effort cleanup
            let _ = std::fs::remove_file(&tmp_path);
            return res;
        }

        let input_path = self
            .input
            .as_deref()
            .ok_or(Error::InvalidOption("input file name is required"))?;
        Self::exec_obfus(input_path, output_path, self)
    }

    fn obfuscate_recursive(&self, dir: &str) -> Result<()> {
        if self.input.is_some() {
            return Err(Error::InvalidOption("both input file name and recursive option are not allowed"));
        }
        if self.input_bytes.is_some() {
            return Err(Error::InvalidOption("input bytes cannot be used with recursive option"));
        }
        if self.output.is_some() {
            eprintln!("output file name will be ignored");
        }

        let entries = util::RecursiveDir::new(dir).map_err(error::Error::Io)?
            .filter_map(|e| Some(e.ok()?.path()))
            .collect::<Vec<_>>();

        for entry in entries.iter() {
            let output_path = format!("obfuscated_dir/{}", entry.to_str().unwrap());
            let parent = output_path.rsplitn(2, '/').collect::<Vec<&str>>()[1];

            std::fs::create_dir_all(parent).map_err(error::Error::Io)?;
            std::fs::File::create(&output_path).map_err(error::Error::CreateFile)?;

            match Self::exec_obfus(entry.to_str().unwrap(), &output_path, self) {
                Ok(_) => (),
                Err(e) => {
                    eprintln!("error while obfuscation of {output_path}: {e}");
                    std::fs::remove_file(&output_path).map_err(error::Error::RemoveFile)?;
                    continue;
                }
            }
        }
        Ok(())
    }

    fn exec_obfus(input_path: &str, output_path: &str, opts: &ObfuscateBuilder) -> Result<()> {
        let loader = Obfuscator::open(input_path, output_path);
        let mut obfuscator = loader?;

        if opts.class {
            let _ = obfuscator.change_class();
        }
        if opts.endian {
            let _ = obfuscator.change_endian();
        }
        if opts.sechdr {
            let _ = obfuscator.nullify_sec_hdr();
        }
        if opts.symbol {
            let _ = obfuscator.nullify_section(".strtab");
        }
        if opts.comment {
            let _ = obfuscator.nullify_section(".comment");
        }
        if let Some(section) = &opts.section {
            let _ = obfuscator.nullify_section(section);
        }
        if opts.got {
            let got_l = opts.got_l.as_deref().ok_or(Error::InvalidOption("both library and function names are required"))?;
            let got_f = opts.got_f.as_deref().ok_or(Error::InvalidOption("both library and function names are required"))?;
            let _ = obfuscator.got_overwrite(got_l, got_f);
        }
        if opts.encrypt {
            let func = opts.encrypt_f.as_deref().ok_or(Error::InvalidOption("target function name and encryption key is required"))?;
            let key = opts.encrypt_key.as_deref().ok_or(Error::InvalidOption("target function name and encryption key is required"))?;
            let _ = obfuscator.encrypt_function_name(func, key);
        }

        Ok(())
    }
}
