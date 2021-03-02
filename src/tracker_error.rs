
use std::any::Any;
use std::convert::From;
use std::error;
use std::fmt;

use TrackerError::*;

#[derive(Debug                                                                          )]
pub enum TrackerError {
    ContextError    (Box<dyn error::Error>),
    DatabaseError   (Box<dyn error::Error>),
    IOError         (Box<dyn error::Error>),
    JsonError       (Box<dyn error::Error>),
    ListError       (Box<dyn error::Error>),
    RegexError      (Box<dyn error::Error>),
    WebError        (Box<dyn error::Error>),
    IPLookupError   (String),
    JsonFmtError    (String),
    NoneError       (String),
}
/*
unsafe impl Send for TrackerError {}
unsafe impl Sync for TrackerError {}
*/
impl error::Error for TrackerError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DatabaseError   (err) |
            IOError         (err) |
            JsonError       (err) |
            WebError        (err) => Some(&**err),
            _ => None,
        }
    }
}

impl fmt::Display for TrackerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ContextError    (err) |
            DatabaseError   (err) |
            IOError         (err) |
            JsonError       (err) |
            RegexError      (err) |
            ListError       (err) |
            WebError        (err) => write!(f, "Tracker Error: {}", &**err),
            JsonFmtError    (msg) => write!(f, "Tracker Error: {}", msg),
            IPLookupError   (msg) => write!(f, "IP Lookup Error: {}", msg),
            NoneError       (msg) => write!(f, "None Error: {}", msg),
        }
    }
}

impl From<regex::Error> for TrackerError {
    fn from(error: regex::Error) -> Self {
        DatabaseError(Box::new(error))
    }
}

impl From<rusqlite::Error> for TrackerError {
    fn from(error: rusqlite::Error) -> Self {
        DatabaseError(Box::new(error))
    }
}

impl From<ureq::Error> for TrackerError {
    fn from(error: ureq::Error) -> Self {
        WebError(Box::new(error))
    }
}

impl From<std::io::Error> for TrackerError {
    fn from(error: std::io::Error) -> Self {
        IOError(Box::new(error))
    }
}

impl From<serde_json::Error> for TrackerError {
    fn from(error: serde_json::Error) -> Self {
        JsonError(Box::new(error))
    }
}

impl From<hexchat_api::ListError> for TrackerError {
    fn from(error: hexchat_api::ListError) -> Self {
        ListError(Box::new(error))
    }
}

impl From<hexchat_api::ContextError> for TrackerError {
    fn from(error: hexchat_api::ContextError) -> Self {
        ContextError(Box::new(error))
    }
}
