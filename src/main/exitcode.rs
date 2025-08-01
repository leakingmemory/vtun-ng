use std::fmt;
use std::process::Termination;

#[derive(Debug,Clone)]
pub struct ErrorCode {
    code: u8
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error code: {}", self.code)
    }
}

impl std::error::Error for ErrorCode {}

impl Termination for ErrorCode {
    fn report(self) -> std::process::ExitCode {
        std::process::ExitCode::from(self.code)
    }
}

pub(crate) struct ExitCode {
    exit_code: Result<(), ErrorCode>
}

impl ExitCode {
    pub fn from_code(code: u8) -> Self {
        Self {
            exit_code: Err(ErrorCode { code })
        }
    }
    pub fn from_error_code(code: &ErrorCode) -> Self {
        Self {
            exit_code: Err(code.clone())
        }
    }
    pub fn ok() -> Self {
        Self {
            exit_code: Ok(())
        }
    }

    pub fn get_exit_code(&self) -> Result<(),ErrorCode> {
        self.exit_code.clone()
    }
}
