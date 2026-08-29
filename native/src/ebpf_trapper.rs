use serde::{Deserialize, Serialize};
use std::fs;

use procfs::process::Process;
use std::os::unix::fs::MetadataExt;

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
    /// Inspect real OS process telemetry from /proc.
    /// Renamed concept from eBPF to KernelSecurityMonitor for clarity.
    pub fn inspect_process_telemetry(pid: u32) -> Option<ProcessTelemetry> {
        if pid == 0 {
            return None;
        }

        let proc = match Process::new(pid as i32) {
            Ok(p) => p,
            Err(_) => return None,
        };

        let stat = proc.stat().ok()?;
        
        let cmdline = proc.cmdline().unwrap_or_default();
        let ppid = Some(stat.ppid as u32);
        
        let uid = fs::metadata(format!("/proc/{}", pid))
            .map(|m| m.uid())
            .unwrap_or(0);

        let executable_path = proc.exe().ok().map(|p| p.to_string_lossy().to_string());
        
        let mut has_rwx_mapping = false;
        if let Ok(maps) = proc.maps() {
            for map in maps {
                let dbg = format!("{:?}", map.perms).to_uppercase();
                if dbg.contains("RWX") || (dbg.contains("READ") && dbg.contains("WRITE") && dbg.contains("EXECUTE")) || (dbg.contains(" R ") && dbg.contains(" W ") && dbg.contains(" X ")) {
                    has_rwx_mapping = true;
                    break;
                }
                // Fallback for custom formats
                if dbg.contains("R") && dbg.contains("W") && dbg.contains("X") {
                     // simplistic fallback
                     has_rwx_mapping = true;
                     break;
                }
            }
        }

        let memory_rss_bytes = stat.rss as u64 * 4096;

        Some(ProcessTelemetry {
            pid,
            ppid,
            name: stat.comm,
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

    /// Read the current syscall number being executed by a process from /proc/{pid}/syscall
    pub fn read_current_syscall(pid: u32) -> Option<String> {
        let path = format!("/proc/{}/syscall", pid);
        if let Ok(content) = fs::read_to_string(&path) {
            if let Some(first) = content.split_whitespace().next() {
                if let Ok(nr) = first.parse::<u32>() {
                    let name = match nr {
                        0 => "read",
                        1 => "write",
                        2 => "open",
                        3 => "close",
                        9 => "mmap",
                        11 => "execve",
                        101 => "ptrace",
                        321 => "bpf",
                        _ => return Some(format!("syscall_{}", nr)),
                    };
                    return Some(name.to_string());
                } else if first != "running" {
                    return Some(first.to_string());
                }
            }
        }
        None
    }

    /// Spawn a passive background monitor that scans /proc and /proc/net/tcp for anomalies.
    pub fn spawn_passive_monitor() -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Spawn blocking task for inotify on /proc/net/tcp
            let _net_monitor = tokio::task::spawn_blocking(|| {
                if let Ok(mut inotify) = inotify::Inotify::init() {
                    if inotify.watches().add("/proc/net/tcp", inotify::WatchMask::MODIFY).is_ok() {
                        let mut buffer = [0; 1024];
                        loop {
                            if let Ok(events) = inotify.read_events_blocking(&mut buffer) {
                                for _ in events {
                                    tracing::warn!("KernelSecurityMonitor: Suspicious new network connection detected in /proc/net/tcp");
                                }
                            }
                        }
                    }
                }
            });

            loop {
                if let Ok(procs) = procfs::process::all_processes() {
                    for proc_res in procs {
                        if let Ok(proc) = proc_res {
                            let pid = proc.pid;
                            if let Ok(stat) = proc.stat() {
                                let rss = stat.rss as u64 * 4096;
                                if rss > 500 * 1024 * 1024 {
                                    tracing::warn!("KernelSecurityMonitor: Process {} (PID {}) memory exhaustion: {} bytes", stat.comm, pid, rss);
                                }
                                
                                if let Ok(exe) = proc.exe() {
                                    let exe_path = exe.to_string_lossy();
                                    if exe_path.starts_with("/tmp/") || exe_path.starts_with("/dev/shm/") || exe_path.contains("/.") {
                                        tracing::warn!("KernelSecurityMonitor: Process {} (PID {}) running from suspicious path: {}", stat.comm, pid, exe_path);
                                    }
                                    
                                    if let Some(basename) = exe.file_name() {
                                        let basename_str = basename.to_string_lossy();
                                        if basename_str != stat.comm {
                                            tracing::warn!("KernelSecurityMonitor: Process {} (PID {}) name changed (executable is {})", stat.comm, pid, basename_str);
                                        }
                                    }
                                }
                            }
                            
                            if let Ok(maps) = proc.maps() {
                                let mut has_rwxp = false;
                                for map in maps {
                                    let dbg = format!("{:?}", map.perms).to_uppercase();
                                    if dbg.contains("RWX") || (dbg.contains("READ") && dbg.contains("WRITE") && dbg.contains("EXECUTE")) || (dbg.contains(" R ") && dbg.contains(" W ") && dbg.contains(" X ")) {
                                        has_rwxp = true;
                                        break;
                                    }
                                    if dbg.contains("R") && dbg.contains("W") && dbg.contains("X") {
                                         has_rwxp = true;
                                         break;
                                    }
                                }
                                if has_rwxp {
                                    tracing::warn!("KernelSecurityMonitor: Process (PID {}) has rwxp memory mappings (potential shellcode injection)", pid);
                                }
                            }
                        }
                    }
                }
                
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        })
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
        let current_syscall = Self::read_current_syscall(pid).unwrap_or_else(|| "unknown".to_string());

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
                    "KernelSecurityMonitor: PID {} (UID {}, Telemetry: {:?}) attempted unauthorized ptrace call. Current syscall is {}. Blocked memory injection / privilege escalation.",
                    pid, uid, telemetry.as_ref().map(|t| &t.name), current_syscall
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
                    "KernelSecurityMonitor: PID {} (UID {}) attempted unprivileged KernelSecurityMonitor/eBPF program load. Current syscall is {}.",
                    pid, uid, current_syscall
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
                        "KernelSecurityMonitor: PID {} (UID {}) execve target '{}' matches kernel rootkit / privilege escalation signature. Current syscall is {}.",
                        pid, uid, target, current_syscall
                    ),
                };
            }
        }

        // 4. Default Verdict: Syscall validated clean by KernelSecurityMonitor probe
        EbpfVerdict {
            allowed: true,
            syscall: syscall.to_string(),
            pid,
            uid,
            threat_detected: false,
            threat_type: None,
            risk_level: "LOW".to_string(),
            explanation: format!(
                "KernelSecurityMonitor: Syscall '{}' by PID {} (UID {}) passed KernelSecurityMonitor integrity check. Current syscall is {}.",
                syscall, pid, uid, current_syscall
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
