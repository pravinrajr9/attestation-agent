use sgx_types::*;
use std::boxed::Box;
use std::error::Error;
use std::fmt;
use std::string::String;

#[derive(Debug)]
struct StaticStrError {
    error: &'static str,
}

impl Error for StaticStrError {
    fn description(&self) -> &str {
        self.error
    }
}

impl fmt::Display for StaticStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.error)
    }
}

#[derive(Debug)]
struct StringError {
    error: String,
}

impl Error for StringError {
    fn description(&self) -> &str {
        &self.error
    }
}

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error: {}", self.error)
    }
}

pub fn static_err(e: &'static str) -> Box<Error> {
    Box::new(StaticStrError { error: e })
}

pub fn new_err(e: &str) -> Box<Error> {
    Box::new(StringError {
        error: String::from(e),
    })
}

pub fn into_err(e: String) -> Box<Error> {
    Box::new(StringError { error: e })
}
