#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext, helpers::bpf_probe_read_user_str_bytes};
use aya_log_ebpf::info;

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    match try_sys_enter_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_execve(ctx: TracePointContext) -> Result<u32, u32> {
    // Read the filename pointer from the tracepoint context (arg 0, usually at offset 16).
    let filename_ptr: *const u8 = unsafe { ctx.read_at(16).map_err(|_| 1u32)? };
    let mut buf = [0u8; 128];
    
    if let Ok(bytes) = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut buf) } {
        if let Ok(s) = core::str::from_utf8(bytes) {
            // Check for malicious paths inline
            if s.contains("rootkit") || s.contains("privesc") || s.contains("/tmp/pwn") {
                info!(&ctx, "SECURITY ALERT: Detected suspicious execve target: {}", s);
                // In a full implementation using a bpf_override_return-enabled kprobe
                // or BPF LSM, we would return -EPERM here to block the syscall natively.
            } else {
                info!(&ctx, "execve: {}", s);
            }
        }
    }
    
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
