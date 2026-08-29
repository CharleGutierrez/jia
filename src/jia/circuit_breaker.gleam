pub type RateLimitStatus {
  Allowed
  RateLimited
  PayloadTooLarge
}

pub const max_body_bytes = 2_097_152

pub const max_requests_per_sec = 300

pub fn evaluate_request(
  request_count: Int,
  body_size_bytes: Int,
) -> RateLimitStatus {
  case body_size_bytes > max_body_bytes {
    True -> PayloadTooLarge
    False ->
      case request_count > max_requests_per_sec {
        True -> RateLimited
        False -> Allowed
      }
  }
}
