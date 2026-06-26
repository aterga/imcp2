//! Optional self-managed Cloudflare quick tunnel.
//!
//! With `--tunnel`, the server spawns `cloudflared tunnel --url
//! http://localhost:<port>`, scrapes the printed
//! `https://<name>.trycloudflare.com` URL from cloudflared's output, and uses it
//! as `PUBLIC_URL` — collapsing the "run cloudflared, copy the URL, restart with
//! PUBLIC_URL set" dance into a single command. HTTPS is required anyway because
//! the id.ai passkey (WebAuthn) only works in a secure context, so a tunnel is
//! unavoidable for real client use.

use std::process::Stdio;
use std::time::Duration;

use anyhow::anyhow;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::oneshot;

/// How long to wait for cloudflared to report its public URL before giving up.
const URL_TIMEOUT: Duration = Duration::from_secs(30);

/// Start a Cloudflare quick tunnel to `http://localhost:<port>` and return the
/// public `https://…trycloudflare.com` URL together with the running child
/// process. Keep the [`Child`] alive for as long as the tunnel is needed —
/// it is configured with `kill_on_drop`, so dropping it tears the tunnel down.
pub async fn start(port: &str) -> anyhow::Result<(String, Child)> {
    let local = format!("http://localhost:{port}");
    tracing::info!("starting cloudflared quick tunnel to {local}");

    let mut child = Command::new("cloudflared")
        .args(["tunnel", "--no-autoupdate", "--url", &local])
        // cloudflared logs (including the URL banner) go to stderr; we don't need
        // stdout, so silence it to avoid filling an unread pipe.
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow!(
                    "`cloudflared` was not found on PATH. Install it and retry, or run \
                     without --tunnel and set PUBLIC_URL yourself.\n  \
                     macOS:  brew install cloudflared\n  \
                     Linux/other:  https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
                )
            } else {
                anyhow::Error::new(e).context("failed to spawn cloudflared")
            }
        })?;

    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("cloudflared stderr was not captured"))?;

    // A long-lived task drains cloudflared's stderr for the lifetime of the
    // process (so its log pipe never fills and stalls the tunnel) and signals the
    // public URL the first time it appears.
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        let mut tx = Some(tx);
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(url) = extract_url(&line) {
                if let Some(tx) = tx.take() {
                    let _ = tx.send(url);
                }
            }
            tracing::debug!(target: "cloudflared", "{line}");
        }
    });

    match tokio::time::timeout(URL_TIMEOUT, rx).await {
        Ok(Ok(url)) => {
            tracing::info!("cloudflared tunnel is up: {url}");
            Ok((url, child))
        }
        // Sender dropped without a URL → stderr closed → cloudflared exited early.
        Ok(Err(_)) => {
            let _ = child.kill().await;
            Err(anyhow!(
                "cloudflared exited before reporting a tunnel URL (is it installed and able to reach Cloudflare?)"
            ))
        }
        Err(_) => {
            let _ = child.kill().await;
            Err(anyhow!(
                "timed out after {}s waiting for cloudflared to report its tunnel URL",
                URL_TIMEOUT.as_secs()
            ))
        }
    }
}

/// Pull the first `https://<name>.trycloudflare.com` URL out of a log line.
/// cloudflared prints it inside an ASCII box, so the URL is delimited by
/// whitespace (and the box's `|` borders) on either side.
fn extract_url(line: &str) -> Option<String> {
    let start = line.find("https://")?;
    let rest = &line[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '|')
        .unwrap_or(rest.len());
    let url = rest[..end].trim_end_matches('/');
    url.ends_with(".trycloudflare.com").then(|| url.to_string())
}

#[cfg(test)]
mod tests {
    use super::extract_url;

    #[test]
    fn extracts_url_from_box_line() {
        let line = "2024-01-01T00:00:00Z INF |  https://happy-cat-1234.trycloudflare.com   |";
        assert_eq!(
            extract_url(line).as_deref(),
            Some("https://happy-cat-1234.trycloudflare.com")
        );
    }

    #[test]
    fn extracts_bare_url() {
        let line = "your tunnel is at https://foo-bar.trycloudflare.com";
        assert_eq!(
            extract_url(line).as_deref(),
            Some("https://foo-bar.trycloudflare.com")
        );
    }

    #[test]
    fn trims_trailing_slash() {
        let line = "https://foo.trycloudflare.com/";
        assert_eq!(
            extract_url(line).as_deref(),
            Some("https://foo.trycloudflare.com")
        );
    }

    #[test]
    fn ignores_unrelated_https_urls() {
        let line = "INF Thank you for trying Cloudflare Tunnel. See https://developers.cloudflare.com";
        assert_eq!(extract_url(line), None);
    }

    #[test]
    fn no_url_returns_none() {
        assert_eq!(extract_url("INF Registered tunnel connection"), None);
    }
}
