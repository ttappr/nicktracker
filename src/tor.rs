
use crate::tracker_error::*;

/// This trait supports a to-string operation that could fail.
///
pub trait Tor {
    type Target;
    
    /// Convert the object to a `Result`, returning `Ok(Target)` on success;
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
            Err(JsonFmtError(
                format!("Failed to convert JSON \
                        `Value` ({:?}) to String.", self)))
        }
    }
}

impl Tor for Result<hexchat_api::FieldValue, hexchat_api::ListError> {
    type Target = String;
    
    /// Convert the result of `ListIterator.get_field("nick")` to a `Result` 
    /// that can be used to get the `String` value of it using the `?` 
    /// operator.
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

impl Tor for Option<hexchat_api::Context> {
    type Target = hexchat_api::Context;
    fn tor(&self) -> Result<Self::Target, TrackerError> 
    {
        use TrackerError::NoContextError;

        match self {
            Some(ctx) => Ok(ctx.clone()),
            None => Err(
                NoContextError("Unavailable.".to_string())
            ),
        }
    }
}

// TODO - Change this trait to consume self so I don't have to do the extra
//        string copy.

impl Tor for Result<Option<String>, hexchat_api::ContextError> {
    type Target = String;
    fn tor(&self) -> Result<Self::Target, TrackerError>
    {
        match self {
            Ok(Some(s)) => Ok(s.clone()),
            Err(err) => Err(TrackerError::from(err.clone())),
            _ => panic!(""),
        }
    }
}

