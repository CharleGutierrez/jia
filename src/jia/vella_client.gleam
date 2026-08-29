import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/json
import gleam/option.{type Option, None, Some}
import gleam/result

pub fn analyze_event(
  base_url: String,
  payload: String,
  source_ip: String,
  prompt: Option(String),
  user_id: Option(String),
) -> Result(String, String) {
  let prompt_val = case prompt {
    Some(p) -> json.string(p)
    None -> json.null()
  }
  let user_id_val = case user_id {
    Some(u) -> json.string(u)
    None -> json.null()
  }

  let body =
    json.object([
      #("payload", json.string(payload)),
      #("source_ip", json.string(source_ip)),
      #("prompt", prompt_val),
      #("user_id", user_id_val),
    ])
    |> json.to_string

  use req <- result.try(
    request.to(base_url <> "/api/v1/analyze_event")
    |> result.map_error(fn(_) { "Invalid URL provided for analyze_event" }),
  )

  let req =
    req
    |> request.set_method(http.Post)
    |> request.set_header("content-type", "application/json")
    |> request.set_body(body)

  case httpc.send(req) {
    Ok(resp) -> Ok(resp.body)
    Error(_) -> Error("Failed to send HTTP request to Vella native sidecar")
  }
}

pub fn quarantine_target(
  base_url: String,
  target: String,
  reason: String,
) -> Result(String, String) {
  let body =
    json.object([
      #("target", json.string(target)),
      #("reason", json.string(reason)),
    ])
    |> json.to_string

  use req <- result.try(
    request.to(base_url <> "/api/v1/quarantine")
    |> result.map_error(fn(_) { "Invalid URL provided for quarantine" }),
  )

  let req =
    req
    |> request.set_method(http.Post)
    |> request.set_header("content-type", "application/json")
    |> request.set_body(body)

  case httpc.send(req) {
    Ok(resp) -> Ok(resp.body)
    Error(_) -> Error("Failed to send HTTP request to Vella native sidecar")
  }
}

pub fn get_health(base_url: String) -> Result(String, String) {
  use req <- result.try(
    request.to(base_url <> "/api/v1/health")
    |> result.map_error(fn(_) { "Invalid URL provided for health check" }),
  )

  let req = request.set_method(req, http.Get)

  case httpc.send(req) {
    Ok(resp) -> Ok(resp.body)
    Error(_) -> Error("Failed to reach Vella native sidecar health endpoint")
  }
}
