// Jia SOAR Playbook: quarantine.rhai
// Automatically triggers multi-vector containment: IP firewall drop, JWT session revocation, and WORM audit recording.

let jwt_res = revoke_jwt(target);
let ip_res = block_ip(target);
let worm_res = record_worm_log(target, reason, "QUARANTINE_AUTOMATED_REMEDIATION");
log_info("Executed automated quarantine playbook for target: " + target);

"PLAYBOOK_QUARANTINE_SUCCESS: " + jwt_res + " | " + ip_res + " | " + worm_res
