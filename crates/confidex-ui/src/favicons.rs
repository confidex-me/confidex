//! Host requests and validated URLs for site icons.
use eframe::egui;

pub enum Image {
    Pixels(egui::ColorImage),
    External,
}
pub type Completion = Box<dyn FnOnce(Result<Image, ()>) + Send>;
pub struct Placement {
    pub token: u32,
    pub slot: u32,
    pub rect: [f32; 4],
    pub clip: [f32; 4],
    pub foreground: bool,
}
pub enum Request {
    Load {
        token: u32,
        url: String,
        done: Completion,
    },
    Clear,
    Proxy(Option<String>),
    Present(Vec<Placement>),
}
pub fn icon_url(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    Some(format!(
        "{}/favicon.ico",
        url.origin().ascii_serialization()
    ))
}
pub fn proxy_url(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none())
    .then(|| url.to_string())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_origin_is_sent_to_the_site() {
        assert_eq!(
            icon_url("https://user:secret@EXAMPLE.com/private?token=secret#part").as_deref(),
            Some("https://example.com/favicon.ico")
        );
        assert_eq!(
            icon_url("http://localhost:4174/private").as_deref(),
            Some("http://localhost:4174/favicon.ico")
        );
        for value in [
            "javascript:alert(1)",
            "file:///private",
            "data:text/plain,secret",
            "not a URL",
        ] {
            assert!(icon_url(value).is_none());
        }
    }
    #[test]
    fn proxy_addresses_have_no_credentials_or_resource_path() {
        assert_eq!(
            proxy_url("http://127.0.0.1:8080").as_deref(),
            Some("http://127.0.0.1:8080/")
        );
        assert!(proxy_url("https://proxy.example:8443").is_some());
        for address in [
            "",
            "file:///proxy",
            "socks5://localhost:9050",
            "https://user:secret@proxy.example",
            "https://proxy.example/private",
            "https://proxy.example/?secret=value",
            "https://proxy.example/#secret",
        ] {
            assert!(proxy_url(address).is_none(), "{address}");
        }
    }
}
