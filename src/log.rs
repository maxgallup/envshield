#![allow(unused)]

/// Custom log level
pub const LOG_LEVEL: LogLevel = LogLevel::Debug;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum LogLevel {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    Disabled = 4,
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::log::LOG_LEVEL as u8 <= $crate::log::LogLevel::Debug as u8 {
            eprintln!("[DEBUG] {}", format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        if $crate::log::LOG_LEVEL as u8 <= $crate::log::LogLevel::Info as u8 {
            eprintln!("[INFO] {}", format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        if $crate::log::LOG_LEVEL as u8 <= $crate::log::LogLevel::Warn as u8 {
            eprintln!("[WARN] {}", format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        if $crate::log::LOG_LEVEL as u8 <= $crate::log::LogLevel::Error as u8 {
            eprintln!("[ERROR] {}", format!($($arg)*));
        }
    };
}
