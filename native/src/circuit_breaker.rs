use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const MAX_BODY_SIZE_BYTES: usize = 2 * 1024 * 1024; // 2MB
pub const MAX_REQUESTS_PER_SECOND: usize = 300;

#[derive(Clone, Debug)]
pub struct RateLimiter {
    history: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            history: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn check_rate_limit(&self, ip: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(1);
        let mut history = self.history.lock().unwrap();

        let timestamps = history.entry(ip.to_string()).or_insert_with(Vec::new);
        timestamps.retain(|&t| now.duration_since(t) < window);

        if timestamps.len() >= MAX_REQUESTS_PER_SECOND {
            false
        } else {
            timestamps.push(now);
            true
        }
    }

    pub fn reset(&self) {
        let mut history = self.history.lock().unwrap();
        history.clear();
    }
}

pub async fn circuit_breaker_middleware<S>(
    State(limiter): State<RateLimiter>,
    req: Request<Body>,
    next: Next,
) -> Response
where
    S: Send + Sync,
{
    // 1. Body Size Guard via Content-Length Header (Zero allocation HTTP 413)
    if let Some(cl_val) = req.headers().get(header::CONTENT_LENGTH) {
        if let Ok(cl_str) = cl_val.to_str() {
            if let Ok(cl) = cl_str.parse::<usize>() {
                if cl > MAX_BODY_SIZE_BYTES {
                    return StatusCode::PAYLOAD_TOO_LARGE.into_response();
                }
            }
        }
    }

    // 2. Extract Source IP from Headers or default to localhost
    let ip_str = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .or_else(|| req.headers().get("x-real-ip").and_then(|h| h.to_str().ok()))
        .unwrap_or("127.0.0.1")
        .trim();

    // 3. Sliding-window Rate Limiter (Zero allocation HTTP 429)
    if !limiter.check_rate_limit(ip_str) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    next.run(req).await
}
