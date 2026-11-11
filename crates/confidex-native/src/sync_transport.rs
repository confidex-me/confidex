use confidex_app::{
    Error,
    sync::{MAX_BODY, Reply, Transport},
};

pub struct Net {
    tcp: reqwest::Client,
    quic: Option<reqwest::Client>,
    origin: String,
    prefer_quic: bool,
    #[cfg(test)]
    last_version: Option<reqwest::Version>,
}
impl Net {
    pub fn new() -> Result<Self, std::io::Error> {
        let builder = || {
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
        };
        let proxy = [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ]
        .iter()
        .any(|name| std::env::var_os(name).is_some_and(|v| !v.is_empty()));
        Ok(Self {
            tcp: builder().build().map_err(std::io::Error::other)?,
            quic: if proxy {
                None
            } else {
                builder().http3_prior_knowledge().build().ok()
            },
            origin: String::new(),
            prefer_quic: false,
            #[cfg(test)]
            last_version: None,
        })
    }
}
impl Transport for Net {
    async fn send(
        &mut self,
        url: &str,
        method: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<Reply, Error> {
        if body.len() > MAX_BODY {
            return Err(Error::Input);
        }
        let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| Error::Input)?;
        let build_request = |client: &reqwest::Client| {
            let mut request = client
                .request(method.clone(), url)
                .header("Cache-Control", "no-store");
            if method == reqwest::Method::HEAD {
                request = request.timeout(std::time::Duration::from_secs(3));
            }
            if !content_type.is_empty() {
                request = request.header("Content-Type", content_type);
            }
            request
        };
        let origin = reqwest::Url::parse(url)
            .map_err(|_| Error::Input)?
            .origin()
            .ascii_serialization();
        let probe = matches!(method, reqwest::Method::GET | reqwest::Method::HEAD)
            && url.starts_with("https://")
            && self.origin != origin
            && self.quic.is_some();
        // Race reads only. Read history before retrying a failed write.
        let mut response = if probe {
            let quic = build_request(self.quic.as_ref().unwrap())
                .version(reqwest::Version::HTTP_3)
                .send();
            let tcp = async {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                build_request(&self.tcp).send().await
            };
            tokio::pin!(quic, tcp);
            tokio::select! {
                result=&mut quic=>match result {Ok(response)=>Ok(response),Err(_)=>tcp.await},
                result=&mut tcp=>match result {Ok(response)=>Ok(response),Err(_)=>quic.await},
            }
            .map_err(|_| Error::Network)?
        } else {
            let client = if self.prefer_quic && self.origin == origin {
                self.quic.as_ref().unwrap_or(&self.tcp)
            } else {
                &self.tcp
            };
            let mut request = build_request(client).body(body);
            if self.prefer_quic && self.origin == origin {
                request = request.version(reqwest::Version::HTTP_3);
            }
            match request.send().await {
                Ok(response) => response,
                Err(_) => {
                    self.prefer_quic = false;
                    if matches!(method, reqwest::Method::GET | reqwest::Method::HEAD) {
                        build_request(&self.tcp)
                            .send()
                            .await
                            .map_err(|_| Error::Network)?
                    } else {
                        return Err(Error::Network);
                    }
                }
            }
        };
        self.origin = origin;
        self.prefer_quic = response.version() == reqwest::Version::HTTP_3;
        #[cfg(test)]
        {
            self.last_version = Some(response.version());
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_BODY as u64)
        {
            return Err(Error::Integrity);
        }
        let mut reply = Reply {
            status: response.status().as_u16(),
            content_type: response
                .headers()
                .get("Content-Type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned(),
            etag: response
                .headers()
                .get("ETag")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            cursor: response
                .headers()
                .get("Sync-Cursor")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            max_body: response
                .headers()
                .get("Sync-Max-Body-Bytes")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok()),
            body: vec![],
        };
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Network)? {
            if reply.body.len() + chunk.len() > MAX_BODY {
                return Err(Error::Integrity);
            }
            reply.body.extend_from_slice(&chunk);
        }
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }
    #[test]
    fn local_http1_and_response_size_limit_work_without_quic() {
        for length in [2, MAX_BODY + 1] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut request = [0; 4096];
                assert!(socket.read(&mut request).unwrap() > 0);
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\nok"
                )
                .unwrap();
            });
            runtime().block_on(async {
                let mut net = Net::new().unwrap();
                net.tcp = reqwest::Client::builder().no_proxy().build().unwrap();
                let result = net
                    .send(&format!("http://{address}/"), "GET", "", vec![])
                    .await;
                if length == 2 {
                    assert_eq!(result.unwrap().body, b"ok");
                    assert_eq!(net.last_version, Some(reqwest::Version::HTTP_11));
                } else {
                    assert!(matches!(result, Err(Error::Integrity)));
                }
            });
            server.join().unwrap();
        }
    }
    #[test]
    #[ignore = "requires the public sync edge and UDP access"]
    fn live_http3_uses_quic() {
        runtime().block_on(async {
            let net = Net::new().unwrap();
            let client = net
                .quic
                .expect("QUIC is unavailable or an HTTP proxy is configured");
            let response = client
                .get("https://sync.confidex.me/v1/openapi.json")
                .version(reqwest::Version::HTTP_3)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.version(), reqwest::Version::HTTP_3);
        });
    }
    #[test]
    #[ignore = "requires the public sync edge"]
    fn unavailable_quic_falls_back_to_http2() {
        runtime().block_on(async {
            let mut net = Net::new().unwrap();
            net.quic = Some(
                reqwest::Client::builder()
                    .http3_prior_knowledge()
                    .no_proxy()
                    .resolve("sync.confidex.me", "127.0.0.1:443".parse().unwrap())
                    .timeout(std::time::Duration::from_secs(3))
                    .build()
                    .unwrap(),
            );
            let response = net
                .send(
                    "https://sync.confidex.me/v1/openapi.json",
                    "GET",
                    "",
                    vec![],
                )
                .await
                .unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(net.last_version, Some(reqwest::Version::HTTP_2));
            assert!(!net.prefer_quic);
        });
    }
}
