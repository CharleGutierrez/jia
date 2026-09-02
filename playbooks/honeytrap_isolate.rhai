// Jia SOAR Playbook: honeytrap_isolate.rhai
// Quarantines automated scanners touching honeypot decoy endpoints.

let ip_res = block_ip(target);
let worm_res = record_worm_log(target, reason, "HONEYPOT_AUTOMATED_ISOLATION");
log_warn("Honeypot violation handled: " + target + " - " + reason);

"PLAYBOOK_HONEYTRAP_ISOLATE_SUCCESS: " + ip_res + " | " + worm_res
