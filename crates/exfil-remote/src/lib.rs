//! Non-interactive remote/local scan sources beyond a plain directory tree.
//!
//! Each of [`ProcessFs`], [`TcpFs`], [`WebFs`], and
//! [`webdriver::WebDriverFs`] implements the engine's
//! [`RemoteFs`](exfil_engine::RemoteFs) trait, so every scanner (secrets,
//! AST, taint, IOC, ClamAV, …) runs on their bytes exactly as on local files.
//! [`netscan`] expands a host/CIDR + port spec into `host:port` targets for
//! [`TcpFs`], and [`target`] resolves a user-typed spec to whichever of these
//! it names, so every front end dispatches a scan the same way.

pub mod netscan;
pub mod proc;
pub mod target;
pub mod tcp;
pub mod web;
pub mod webdriver;
pub use proc::ProcessFs;
pub use target::Target;
pub use tcp::TcpFs;
pub use web::WebFs;
