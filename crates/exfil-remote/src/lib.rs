//! Non-interactive remote/local scan sources beyond a plain directory tree.
//!
//! Each of [`ProcessFs`], [`TcpFs`], [`WebFs`], and
//! [`webdriver::WebDriverFs`] implements the engine's
//! [`RemoteFs`](exfil_engine::RemoteFs) trait, so every scanner (secrets,
//! AST, taint, IOC, ClamAV, …) runs on their bytes exactly as on local files.
//! [`netscan`] expands a host/CIDR + port spec into `host:port` targets for
//! [`TcpFs`].

pub mod netscan;
pub mod proc;
pub mod tcp;
pub mod web;
pub mod webdriver;
pub use proc::ProcessFs;
pub use tcp::TcpFs;
pub use web::WebFs;
