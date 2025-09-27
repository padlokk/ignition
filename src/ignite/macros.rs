//! Ignite module macros.
//!
//! Keep macros thin; they delegate to helpers within `ignite` modules.
//! Additional macros will be introduced as the authority implementation grows.

// pub use crate::ignite::utils::some_helper;

// Example placeholder macro (kept unused intentionally)
#[macro_export]
macro_rules! ignite_todo {
    () => {
        compile_error!("ignite macro surface not implemented yet");
    };
}
