use std::net::SocketAddr;

pub struct TestClient {
    pub http: reqwest::Client,
    pub base_url: String,
    pub api_key: String,
}

impl TestClient {
    pub fn new(http_addr: SocketAddr, api_key: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: format!("http://{http_addr}"),
            api_key: api_key.to_string(),
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }
}
