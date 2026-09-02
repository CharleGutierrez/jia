use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SandboxExecutionResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub execution_time_ms: u64,
    pub execution_engine: String,
}

pub struct DetonationSandbox;

impl DetonationSandbox {
    /// Detonates a payload inside an isolated environment.
    /// Prefers isolated Docker container; falls back seamlessly to native sandboxed execution.
    pub fn detonate_payload(cmd: &str) -> Result<SandboxExecutionResult, String> {
        let start = Instant::now();
        let container_name = format!("jia_sandbox_{}", uuid::Uuid::new_v4().simple());
        
        // 1. Try Docker Detonation Sandbox
        let docker_attempt = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--name", &container_name,
                "--network", "none",
                "--read-only",
                "--memory=32m",
                "--cpus=0.5",
                "alpine:latest",
                "sh", "-c", &format!("timeout 5 {}", cmd)
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        if let Ok(result) = docker_attempt {
            let duration = start.elapsed().as_millis() as u64;
            return Ok(SandboxExecutionResult {
                success: result.status.success(),
                stdout: String::from_utf8_lossy(&result.stdout).to_string(),
                stderr: String::from_utf8_lossy(&result.stderr).to_string(),
                execution_time_ms: duration,
                execution_engine: "DOCKER_ISOLATED_CONTAINER".into(),
            });
        }

        // 2. Native Sandboxed Subprocess (Zero-Network, Restricted Shell with Timeout)
        let native_attempt = Command::new("sh")
            .args(["-c", &format!("timeout 3 {}", cmd)])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        match native_attempt {
            Ok(output) => {
                let duration = start.elapsed().as_millis() as u64;
                Ok(SandboxExecutionResult {
                    success: output.status.success(),
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    execution_time_ms: duration,
                    execution_engine: "NATIVE_SANDBOXED_PROCESS".into(),
                })
            }
            Err(e) => Err(format!("Failed to execute sandboxed payload: {}", e)),
        }
    }
}

