use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::de::DeserializeOwned;

pub struct DaemonClient {
    socket_path: PathBuf,
}

impl DaemonClient {
    pub fn new(socket_path: &Path) -> Self {
        Self {
            socket_path: socket_path.to_path_buf(),
        }
    }

    fn build_client(&self) -> Client<UnixConnector, Full<Bytes>> {
        let connector = UnixConnector {
            path: self.socket_path.clone(),
        };
        Client::builder(TokioExecutor::new()).build(connector)
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let client = self.build_client();
        let uri = format!("http://localhost{path}");
        let resp = client
            .get(uri.parse().unwrap())
            .await
            .context("Failed to connect to daemon. Is misp-fbd running?")?;

        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .context("Failed to read response body")?
            .to_bytes();

        if !status.is_success() {
            bail!(
                "Daemon returned HTTP {}: {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }

        serde_json::from_slice(&body).context("Failed to parse response JSON")
    }

    pub async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        let client = self.build_client();
        let uri = format!("http://localhost{path}");
        let json = serde_json::to_vec(body)?;

        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(json)))
            .unwrap();

        let resp = client
            .request(req)
            .await
            .context("Failed to connect to daemon. Is misp-fbd running?")?;

        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .context("Failed to read response body")?
            .to_bytes();

        if !status.is_success() {
            bail!(
                "Daemon returned HTTP {}: {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }

        serde_json::from_slice(&body).context("Failed to parse response JSON")
    }
}

// Newtype wrapper so we can implement Connection for it (orphan rules)
struct UnixStream(hyper_util::rt::TokioIo<tokio::net::UnixStream>);

impl hyper::rt::Read for UnixStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for UnixStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Unpin for UnixStream {}

impl hyper_util::client::legacy::connect::Connection for UnixStream {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

// Unix socket connector for hyper-util's legacy Client
#[derive(Clone)]
struct UnixConnector {
    path: PathBuf,
}

impl tower::Service<hyper::Uri> for UnixConnector {
    type Response = UnixStream;
    type Error = std::io::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: hyper::Uri) -> Self::Future {
        let path = self.path.clone();
        Box::pin(async move {
            let stream = tokio::net::UnixStream::connect(path).await?;
            Ok(UnixStream(hyper_util::rt::TokioIo::new(stream)))
        })
    }
}
