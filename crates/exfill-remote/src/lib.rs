//! Remote scanning over SSH/SFTP.
//!
//! [`SshFs`] implements the engine's [`RemoteFs`](exfill_engine::RemoteFs) trait
//! against a real host: it walks the remote filesystem over SFTP and streams
//! file bytes back, so every scanner (secrets, AST, taint, IOC, ClamAV, …) runs
//! on remote files exactly as on local ones. Pure Rust via `russh` — no
//! libssh2, no C.
//!
//! A [`RemoteTarget`] parses the SCP-style `[user@]host:/path` destination.
//! Authentication tries, in order: the SSH agent, an explicit private key, then
//! a password — whatever [`SshAuth`] provides.
//!
//! The same [`RemoteFs`] seam also backs [`ProcessFs`], which exposes the local
//! host's *running processes* as scannable bytes — see [`proc`].

pub mod proc;
pub mod tcp;
pub use proc::ProcessFs;
pub use tcp::TcpFs;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use exfill_engine::RemoteFs;
use russh::client;
use russh_sftp::client::SftpSession;
use tokio::io::AsyncReadExt;

/// A parsed remote destination: `user@host:/path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteTarget {
    /// Login user.
    pub user: String,
    /// Hostname or IP.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Remote root path to scan.
    pub path: String,
}

impl RemoteTarget {
    /// Parse `[user@]host[:/path]`. Without a user, falls back to `$USER` (or
    /// `root`). Without a path, scans `/`. `port` comes from the caller.
    pub fn parse(spec: &str, port: u16) -> Result<Self> {
        let (user, rest) = match spec.split_once('@') {
            Some((u, r)) if !u.is_empty() => (u.to_string(), r),
            _ => (
                std::env::var("USER").unwrap_or_else(|_| "root".into()),
                spec,
            ),
        };
        let (host, path) = match rest.split_once(':') {
            Some((h, p)) => (h, if p.is_empty() { "/" } else { p }),
            None => (rest, "/"),
        };
        if host.is_empty() {
            bail!("remote target {spec:?} has no host");
        }
        Ok(Self {
            user,
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }
}

/// How to authenticate to the remote host. Agent-based auth is a follow-up;
/// today a key file or a password is supported.
#[derive(Debug, Clone)]
pub enum SshAuth {
    /// Use a private key file, with an optional passphrase.
    Key(PathBuf, Option<String>),
    /// Use a password.
    Password(String),
}

/// Accepts any host key. Host-key verification against `known_hosts` is a
/// follow-up; for now remote scans trust the endpoint the user named.
struct AcceptAll;

#[async_trait::async_trait]
impl client::Handler for AcceptAll {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A connected SSH/SFTP session exposing a host's files to the scan engine.
pub struct SshFs {
    host: String,
    sftp: SftpSession,
}

impl SshFs {
    /// Connect to `target` and authenticate with `auth`.
    pub async fn connect(target: &RemoteTarget, auth: &SshAuth) -> Result<Self> {
        let config = Arc::new(client::Config::default());
        let mut handle = client::connect(config, (target.host.as_str(), target.port), AcceptAll)
            .await
            .with_context(|| format!("connect {}:{}", target.host, target.port))?;

        let authed = match auth {
            SshAuth::Password(pw) => handle
                .authenticate_password(target.user.clone(), pw.clone())
                .await
                .context("password auth")?,
            SshAuth::Key(path, passphrase) => {
                let key = russh::keys::load_secret_key(path, passphrase.as_deref())
                    .with_context(|| format!("load private key {}", path.display()))?;
                handle
                    .authenticate_publickey(target.user.clone(), Arc::new(key))
                    .await
                    .context("publickey auth")?
            }
        };
        if !authed {
            bail!("authentication failed for {}@{}", target.user, target.host);
        }

        let channel = handle
            .channel_open_session()
            .await
            .context("open session channel")?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .context("request sftp subsystem")?;
        let sftp = SftpSession::new(channel.into_stream())
            .await
            .context("start sftp session")?;

        Ok(Self {
            host: target.host.clone(),
            sftp,
        })
    }
}

#[async_trait::async_trait]
impl RemoteFs for SshFs {
    fn host(&self) -> &str {
        &self.host
    }

    async fn list(&self, root: &str) -> Result<Vec<String>> {
        // Iterative directory walk over SFTP; symlinks are not followed.
        let mut files = Vec::new();
        let mut dirs = vec![root.to_string()];
        while let Some(dir) = dirs.pop() {
            let entries = match self.sftp.read_dir(&dir).await {
                Ok(e) => e,
                Err(_) => continue, // unreadable dir: skip, keep going
            };
            for entry in entries {
                let name = entry.file_name();
                if name == "." || name == ".." {
                    continue;
                }
                let full = if dir.ends_with('/') {
                    format!("{dir}{name}")
                } else {
                    format!("{dir}/{name}")
                };
                if entry.file_type().is_dir() {
                    dirs.push(full);
                } else if entry.file_type().is_file() {
                    files.push(full);
                }
            }
        }
        Ok(files)
    }

    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let mut file = self
            .sftp
            .open(path)
            .await
            .with_context(|| format!("open remote {path}"))?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .await
            .with_context(|| format!("read remote {path}"))?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_user_host_path() {
        let t = RemoteTarget::parse("deploy@web1:/srv/app", 22).unwrap();
        assert_eq!(t.user, "deploy");
        assert_eq!(t.host, "web1");
        assert_eq!(t.port, 22);
        assert_eq!(t.path, "/srv/app");
    }

    #[test]
    fn defaults_path_to_root_and_custom_port() {
        let t = RemoteTarget::parse("alice@10.0.0.5", 2222).unwrap();
        assert_eq!(t.host, "10.0.0.5");
        assert_eq!(t.path, "/");
        assert_eq!(t.port, 2222);
    }

    #[test]
    fn defaults_user_when_absent() {
        std::env::set_var("USER", "ci");
        let t = RemoteTarget::parse("host:/etc", 22).unwrap();
        assert_eq!(t.user, "ci");
        assert_eq!(t.host, "host");
        assert_eq!(t.path, "/etc");
    }

    #[test]
    fn rejects_empty_host() {
        assert!(RemoteTarget::parse("user@:/path", 22).is_err());
    }
}
