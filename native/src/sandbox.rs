use std::process::Command;

pub struct DetonationSandbox;

impl DetonationSandbox {
    /// Detonates a payload inside an isolated, ephemeral Docker container.
    /// Applies strict constraints: no network access, read-only filesystem, 
    /// limited memory and CPU, and a strict 5-second execution timeout.
    pub fn detonate_payload(cmd: &str) -> Result<String, String> {
        let container_name = format!("jia_sandbox_{}", uuid::Uuid::new_v4().simple());
        
        let result = Command::new("docker")
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
            .output()
            .map_err(|e| format!("Failed to spawn sandbox: {}", e))?;

        if result.status.success() {
            Ok(String::from_utf8_lossy(&result.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&result.stderr).to_string())
        }
    }
}
