// Jia SOAR Playbook: revoke_jwt.rhai
// Revokes active session tokens and user identity tokens across Redis & local auth caches.

let jwt_res = revoke_jwt(target);
let worm_res = record_worm_log(target, reason, "JWT_REVOCATION");
log_info("Executed JWT revocation playbook for user/token: " + target);

"PLAYBOOK_JWT_REVOKE_SUCCESS: " + jwt_res + " | " + worm_res
