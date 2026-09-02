// Jia SOAR Playbook: ip_block.rhai
// Adds firewall drop rules for malicious IP addresses and commits audit trail to WORM chain.

let ip_res = block_ip(target);
let worm_res = record_worm_log(target, reason, "IP_FIREWALL_BLOCK");
log_info("Executed IP block playbook for IP: " + target);

"PLAYBOOK_IP_BLOCK_SUCCESS: " + ip_res + " | " + worm_res
