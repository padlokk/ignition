//! Ignite module macros.
//!
//! Keep macros thin; they delegate to helpers within `ignite` modules.
//! Additional macros will be introduced as the authority implementation grows.

// NOTE: ignite_todo! macro is intentionally defined with compile_error!
// to prevent accidental usage during development. It serves as a placeholder
// for future macro surface expansion and will fail compilation if invoked.
// This is by design - it will not break builds unless explicitly used in code.

#[macro_export]
macro_rules! ignite_todo {
    () => {
        compile_error!("ignite macro surface not implemented yet");
    };
}
