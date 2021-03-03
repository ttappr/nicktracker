
//! To Result Module - The `Tor` trait is used to patch return values with a 
//! method, `.tor()` that converts their return values to a `Return` value 
//! compatible with code blocks that return `Result`s with a `TrackerError` 
//! `Err` value.
//! This makes it so the `?` operator can be applied:
//! ```
//! fn get_foo(bar: &Bar) -> Result<Foo, TrackerError> {
//!     let baz = bar.get_baz_might_error()?;
//!     let qux = baz.get_qux_option().tor()?;
//!     qux.foo.clone()
//! }
//! ```
//! This is used to simplify code with a lot of potential failure points.

use crate::tracker_error::*;

use hexchat_api::Context;
use hexchat_api::ContextError;
use hexchat_api::ThreadSafeContext;
use hexchat_api::ThreadSafeListIterator;
use hexchat_api::ThreadSafeFieldValue;

/// This trait supports a to-`Result` operation.
///
pub trait Tor {
    type Target;
    
    /// Convert the object to a `Result`, returning `Ok(Target)` on success, and
    /// `Err(TrackerError)` on failure.
    ///
    fn tor(&self) -> Result<Self::Target, TrackerError>;
}

impl Tor for serde_json::Value {
    type Target = String;
    
    /// Convert the JSON `Value` object to a `Result`.
    /// # Returns
    /// * `Ok(String)` on success, `Err(JsonFmtError)` on failure.
    ///
    fn tor(&self) -> Result<Self::Target, TrackerError> 
    {
        use TrackerError::JsonFmtError;

        if let Some(s) = self.as_str() {
            Ok(s.to_string())
        } else {
            Ok(format!("{}", self))
            /*
            Err(JsonFmtError(
                format!("Failed to convert JSON \
                        `Value` ({:?}) to String.", self)))
             */
        }
    }
}

impl Tor for Result<hexchat_api::FieldValue, hexchat_api::ListError> {
    type Target = String;
    
    /// Convert the result of `ListIterator` functions that return a `Result`
    /// with a string as `Ok(<string>)`. For instance, `.get_field("nick")`.
    ///
    fn tor(&self) -> Result<Self::Target, TrackerError> 
    {
        match self {
            Ok(field_val) => {
                Ok(field_val.to_string())
            },
            Err(list_err) => {
                Err(TrackerError::from(list_err.clone()))
            },
        }
    }
}

impl Tor for Option<Context> {
    type Target = Context;
    
    /// Convert an `Option<Context>` to `Result<Context, NoneError>`.
    ///
    fn tor(&self) -> Result<Self::Target, TrackerError> 
    {
        match self {
            Some(ctx) => Ok(ctx.clone()),
            None => Err(
                TrackerError::NoneError("Context unavailable.".to_string())
            ),
        }
    }
}

impl Tor for Option<ThreadSafeContext> {
    type Target = ThreadSafeContext;
    
    /// Convert an `Option<Context>` to `Result<Context, NoneError>`.
    ///
    fn tor(&self) -> Result<Self::Target, TrackerError> 
    {
        match self {
            Some(ctx) => Ok(ctx.clone()),
            None => Err(
                TrackerError::NoneError("Context unavailable.".to_string())
            ),
        }
    }
}

impl Tor for Option<ThreadSafeListIterator> {
    type Target = ThreadSafeListIterator;
    
    fn tor(&self) -> Result<Self::Target, TrackerError>
    {
        match self {
            Some(list_iter) => Ok(list_iter.clone()),
            None => Err(
                TrackerError::NoneError(
                    "ListIterator unavailable.".to_string()
                )),
        }
    }
}

impl Tor for Result<ThreadSafeFieldValue, hexchat_api::ListError> {
    type Target = String;
    
    fn tor(&self) -> Result<Self::Target, TrackerError>
    {
        match self {
            Ok(field_val) => Ok(field_val.to_string()),
            Err(err) => Err(TrackerError::from(err.clone())),
        }
    }
}

impl Tor for Option<hexchat_api::ListIterator> {
    type Target = hexchat_api::ListIterator;
    
    fn tor(&self) -> Result<Self::Target, TrackerError>
    {
        match self {
            Some(list_iter) => Ok(list_iter.clone()),
            None => Err(
                TrackerError::NoneError("ListIterator unavailable.".to_string())
            ),
        }
    }
}

impl Tor for Result<Option<String>, ContextError> {
    type Target = String;
    
    /// Convert `Result<Option<String>, ContextError>` to 
    /// `Result<String, TrackerError>`.
    ///
    fn tor(&self) -> Result<Self::Target, TrackerError>
    {
        match self {
            Ok(opt) => {
                match opt {
                    Some(s) => Ok(s.clone()),
                    None => Err(
                        TrackerError::NoneError("Failed to retrieve the \
                                                 requested `Context`."
                                                 .to_string())),
                }
            },
            Err(err) => Err(TrackerError::from(err.clone())),
        }
    }
}

impl Tor for Result<Option<ThreadSafeListIterator>, ContextError> {
    type Target = ThreadSafeListIterator;
    fn tor(&self) -> Result<Self::Target, TrackerError>
    {
        match self {
            Ok(opt) => {
                match opt {
                    Some(list) => Ok(list.clone()),
                    None => Err(
                        TrackerError::NoneError("TreadSafeListIterator \
                                                 unavailable.".to_string())),
                }
            },
            Err(err) => Err(TrackerError::from(err.clone())),
        }
    }
}








