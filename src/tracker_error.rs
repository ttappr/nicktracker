
//! This module provides an error class/struct for the nick tracker with 
//! `From` implementations to convert the errors generated by the other
//! crates.

use std::convert::From;
use std::error;
use std::fmt;

use TrackerError::*;

/// The error type used exclusively throughout the application code, and all
/// other errors can be converted to.
///
#[allow(dead_code, clippy::enum_variant_names)]
#[derive(Debug)]
pub enum TrackerError {
    ContextError    (Box<dyn error::Error>),
    DatabaseError   (Box<dyn error::Error>),
    IOError         (Box<dyn error::Error>),
    JsonError       (Box<dyn error::Error>),
    ListError       (Box<dyn error::Error>),
    RegexError      (Box<dyn error::Error>),
    WebError        (Box<dyn error::Error>),
    ConnectionError (String),
    IPLookupError   (String),
    JsonFmtError    (String),
    NoneError       (String),
}
/*
unsafe impl Send for TrackerError {}
unsafe impl Sync for TrackerError {}
*/
impl error::Error for TrackerError {
    /// Converts the base `Error` type to a `TrackerError`.
    ///
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
    /// Formats the error information suitable for printing to the Hexchat
    /// window.
    /// # Variants
    /// * `ContextError`  - Errors regarding Hexchat context usage problems.
    /// * `DatabaseError` - Sqlite3 database errors.
    /// * `IOError`       - io errors.
    /// * `JsonError`     - Errors related to parsing JSON.
    /// * `RegexError`    - Regular expression errors.
    /// * `ListError`     - Hexchat list errors.
    /// * `WebError`      - HTTP request errors.
    /// * `JsonFmtError`  - Errors related to formatting/parsing JSON.
    /// * `IPLookupError` - Errors related to the web service that provides
    ///                     geolocation data.
    /// * `NoneError`     - Can be issued by the `Tor` (to-result) module
    ///                     when an `Option` is `None` to indicate that as an
    ///                     error.
    ///
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ContextError    (err) |
            DatabaseError   (err) |
            IOError         (err) |
            JsonError       (err) |
            RegexError      (err) |
            ListError       (err) |
            WebError        (err) => write!(f, "Tracker Error: {}", &**err),
            ConnectionError (msg) => write!(f, "Connection Error: {}", msg),
            JsonFmtError    (msg) => write!(f, "Tracker Error: {}", msg),
            IPLookupError   (msg) => write!(f, "IP Lookup Error: {}", msg),
            NoneError       (msg) => write!(f, "None Error: {}", msg),
        }
    }
}

impl From<regex::Error> for TrackerError {
    /// Converts errors generated by the `regex` crate to `TrackerError`s.
    ///
    fn from(error: regex::Error) -> Self {
        DatabaseError(Box::new(error))
    }
}

impl From<rusqlite::Error> for TrackerError {
    /// Converts errors generated by `rusqlite` crate to `TrackerError`s.
    ///
    fn from(error: rusqlite::Error) -> Self {
        DatabaseError(Box::new(error))
    }
}

impl From<ureq::Error> for TrackerError {
    /// Converts errors generated by the HTTP request package, `ureq`, to 
    /// `TrackerError`s.
    ///
    fn from(error: ureq::Error) -> Self {
        WebError(Box::new(error))
    }
}

impl From<std::io::Error> for TrackerError {
    /// Converts io errors to `TrackerError`s.
    ///
    fn from(error: std::io::Error) -> Self {
        IOError(Box::new(error))
    }
}

impl From<serde_json::Error> for TrackerError {
    /// Converts errors generated by the `serde` crate (used to process JSON)
    /// to `TrackerError`s.
    ///
    fn from(error: serde_json::Error) -> Self {
        JsonError(Box::new(error))
    }
}

impl From<hexchat_api::HexchatError> for TrackerError {
    /// Converts list errors generated by the `hexchat_api` crate to 
    /// `TrackerError`s.
    ///
    fn from(error: hexchat_api::HexchatError) -> Self {
        use hexchat_api::HexchatError as HE;
        match error {
            HE::ListFieldNotFound(_)      |
            HE::ListIteratorDropped(_)    |
            HE::ListIteratorNotStarted(_) |
            HE::ListNotFound(_)           => ListError(Box::new(error)),
            err => ContextError(Box::new(err)),
        }
    }
}
