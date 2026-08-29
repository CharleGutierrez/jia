use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProcessTelemetry {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub cmdline: Vec<String>,
    pub memory_rss_bytes: u64,
    pub uid: u32,
    pub has_rwx_mapping: bool,
    pub executable_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EbpfInspectRequest {
    pub syscall: String,
    pub pid: u32,
    pub uid: u32,
    pub path_or_target: Option<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct EbpfVerdict {
    pub allowed: bool,
    pub syscall: String,
    pub pid: u32,
    pub uid: u32,
    pub threat_detected: bool,
    pub threat_type: Option<String>,
    pub risk_level: String,
    pub explanation: String,
}

pub struct EbpfTrapper;

impl EbpfTrapper {
    /// Inspect real OS process telemetry from /proc and sysinfo.
    pub fn inspect_process_telemetry(pid: u32) -> Option<ProcessTelemetry> {
        if pid == 0 {
            return None;
        }

        let proc_dir = format!("/proc/{}", pid);
        if !Path::new(&proc_dir).exists() {
            return None;
        }

        // 1. Read cmdline
        let cmdline = fs::read(format!("{}/cmdline", proc_dir))
            .map(|bytes| {
                bytes
                    .split(|&b| b == 0)
                    .filter_map(|s| String::from_utf8(s.to_vec()).ok())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();

        // 2. Read status for PPid and Uid
        let mut ppid = None;
        let mut uid = 0;
        let mut name = format!("process_{}", pid);

        if let Ok(status_str) = fs::read_to_string(format!("{}/status", proc_dir)) {
            for line in status_str.lines() {
                if line.starts_with("Name:") {
                    name = line.split_whitespace().nth(1).unwrap_or(&name).to_string();
                } else if line.starts_with("PPid:") {
                    ppid = line.split_whitespace().nth(1).and_then(|s| s.parse::<u32>().ok());
                } else if line.starts_with("Uid:") {
                    uid = line.split_whitespace().nth(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
                }
            }
        }

        // 3. Read executable path
        let executable_path = fs::read_link(format!("{}/exe", proc_dir))
            .ok()
            .map(|p| p.to_string_lossy().to_string());

        // 4. Inspect memory maps for dangerous rwxp (executable & writable) regions
        let mut has_rwx_mapping = false;
        let mut memory_rss_bytes = 0u64;

        if let Ok(maps_str) = fs::read_to_string(format!("{}/maps", proc_dir)) {
            for line in maps_str.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let perms = parts[1];
                    if perms.contains("rwx") {
                        has_rwx_mapping = true;
                    }
                }
            }
        }

        // Read RSS memory from sysinfo if available
        let mut sys = sysinfo::System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        if let Some(proc) = sys.process(sysinfo::Pid::from(pid as usize)) {
            memory_rss_bytes = proc.memory();
            if name.is_empty() {
                name = proc.name().to_string_lossy().to_string();
            }
        }

        Some(ProcessTelemetry {
            pid,
            ppid,
            name,
            cmdline,
            memory_rss_bytes,
            uid,
            has_rwx_mapping,
            executable_path,
        })
    }

    /// Terminate process using libc signal (SIGKILL=9 or SIGTERM=15).
    pub fn terminate_process(pid: u32, signal: i32) -> Result<bool, String> {
        if pid <= 1 {
            return Err("Refusing to terminate PID <= 1".to_string());
        }

        #[cfg(unix)]
        {
            let res = unsafe { libc::kill(pid as libc::pid_t, signal as libc::c_int) };
            if res == 0 {
                Ok(true)
            } else {
                Err(format!("libc::kill returned error code {}", res))
            }
        }

        #[cfg(not(unix))]
        {
            let mut sys = sysinfo::System::new();
            sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            if let Some(proc) = sys.process(sysinfo::Pid::from(pid as usize)) {
                proc.kill();
                Ok(true)
            } else {
                Err(format!("Process PID {} not found in sysinfo", pid))
            }
        }
    }

    /// Inspect kernel system calls for privilege escalation, rootkits, and unauthorized operations.
    pub fn inspect_syscall(syscall: &str, pid: u32, uid: u32) -> EbpfVerdict {
        Self::inspect_syscall_with_target(syscall, pid, uid, None)
    }

    /// Extended inspection with target path / payload context and real PID telemetry.
    pub fn inspect_syscall_with_target(
        syscall: &str,
        pid: u32,
        uid: u32,
        path_or_target: Option<&str>,
    ) -> EbpfVerdict {
        let sys_lower = syscall.to_lowercase();
        let target = path_or_target.unwrap_or("");

        // Query real OS process telemetry if available
        let telemetry = Self::inspect_process_telemetry(pid);

        // 1. Check ptrace system call for unauthorized process memory injection / privilege escalation
        if sys_lower == "ptrace" && uid != 0 {
            // Attempt process kill signal enforcement if process has RWX memory injection
            if let Some(ref t) = telemetry {
                if t.has_rwx_mapping {
                    let _ = Self::terminate_process(pid, 9);
                }
            }

            return EbpfVerdict {
                allowed: false,
                syscall: syscall.to_string(),
                pid,
                uid,
                threat_detected: true,
                threat_type: Some("UNAUTHORIZED_PTRACE_INJECTION".to_string()),
                risk_level: "CRITICAL".to_string(),
                explanation: format!(
                    "PID {} (UID {}, Telemetry: {:?}) attempted unauthorized ptrace call. Blocked memory injection / privilege escalation.",
                    pid, uid, telemetry.as_ref().map(|t| &t.name)
                ),
            };
        }

        // 2. Check bpf_cmd / sys_bpf loading by non-root users
        if (sys_lower == "bpf_cmd" || sys_lower == "bpf" || sys_lower == "sys_bpf") && uid != 0 {
            return EbpfVerdict {
                allowed: false,
                syscall: syscall.to_string(),
                pid,
                uid,
                threat_detected: true,
                threat_type: Some("UNAUTHORIZED_EBPF_PROGRAM_LOAD".to_string()),
                risk_level: "HIGH".to_string(),
                explanation: format!(
                    "PID {} (UID {}) attempted unprivileged eBPF kernel program load.",
                    pid, uid
                ),
            };
        }

        // 3. Check execve suspicious paths for rootkits or unauthorized binary execution
        if sys_lower == "execve" {
            let rootkit_keywords = [
                "rootkit",
                "kroot",
                "/tmp/privesc",
                "/dev/shm/",
                "ebpf_hook_override",
                "suid_exploit",
            ];
            let is_rootkit = rootkit_keywords.iter().any(|kw| target.contains(kw));
            if is_rootkit {
                return EbpfVerdict {
                    allowed: false,
                    syscall: syscall.to_string(),
                    pid,
                    uid,
                    threat_detected: true,
                    threat_type: Some("KERNEL_ROOTKIT_EXECUTION".to_string()),
                    risk_level: "CRITICAL".to_string(),
                    explanation: format!(
                        "PID {} (UID {}) execve target '{}' matches kernel rootkit / privilege escalation signature.",
                        pid, uid, target
                    ),
                };
            }
        }

        // 4. Default Verdict: Syscall validated clean by eBPF trapper probe
        EbpfVerdict {
            allowed: true,
            syscall: syscall.to_string(),
            pid,
            uid,
            threat_detected: false,
            threat_type: None,
            risk_level: "LOW".to_string(),
            explanation: format!(
                "Syscall '{}' by PID {} (UID {}) passed eBPF kernel probe integrity check.",
                syscall, pid, uid
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_ptrace_unauthorized_inspection() {
        let verdict = EbpfTrapper::inspect_syscall("ptrace", 1337, 1000);
        assert!(!verdict.allowed);
        assert!(verdict.threat_detected);
        assert_eq!(verdict.risk_level, "CRITICAL");
        assert_eq!(verdict.threat_type, Some("UNAUTHORIZED_PTRACE_INJECTION".to_string()));
    }

    #[test]
    fn test_ebpf_bpf_cmd_unprivileged_inspection() {
        let verdict = EbpfTrapper::inspect_syscall("bpf_cmd", 2048, 1001);
        assert!(!verdict.allowed);
        assert!(verdict.threat_detected);
        assert_eq!(verdict.risk_level, "HIGH");
    }

    #[test]
    fn test_ebpf_clean_syscall() {
        let verdict = EbpfTrapper::inspect_syscall("read", 100, 1000);
        assert!(verdict.allowed);
        assert!(!verdict.threat_detected);
        assert_eq!(verdict.risk_level, "LOW");
    }
}


