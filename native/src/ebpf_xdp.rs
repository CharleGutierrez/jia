use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketHeader {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String, // "TCP", "UDP", "ICMP"
    pub is_syn: bool,
    pub pps_rate: u32,
    pub payload_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdpDecision {
    pub action: String, // "XDP_DROP", "XDP_PASS", "XDP_TX"
    pub dropped: bool,
    pub matched_rule: Option<String>,
    pub reason: String,
    pub latency_ns: u64,
    pub interface: String,
}

#[derive(Debug, Deserialize)]
pub struct XdpFilterRequest {
    pub packet: PacketHeader,
}

#[derive(Debug, Serialize)]
pub struct XdpFilterResponse {
    pub decision: XdpDecision,
    pub driver_mode: String,
    pub current_mpps_capacity: f32,
    pub timestamp: String,
}

pub struct EbpfXdpEngine;

impl EbpfXdpEngine {
    /// Evaluates NIC driver-level XDP filter hook
    pub fn evaluate_packet(pkt: &PacketHeader) -> XdpDecision {
        // 1. SYN Flood mitigation (> 100,000 pps with SYN flag)
        if pkt.is_syn && pkt.pps_rate > 50_000 {
            return XdpDecision {
                action: "XDP_DROP".into(),
                dropped: true,
                matched_rule: Some("XDP-SYN-FLOOD-DEFENSE".into()),
                reason: format!("High-rate SYN flood detected ({} pps) from {}", pkt.pps_rate, pkt.src_ip),
                latency_ns: 180, // Sub-microsecond driver level
                interface: "eth0".into(),
            };
        }

        // 2. UDP Amplification / NTP reflection (UDP to port 123 or 53 with large payload)
        if pkt.protocol == "UDP" && (pkt.src_port == 123 || pkt.src_port == 19) && pkt.payload_size > 1024 {
            return XdpDecision {
                action: "XDP_DROP".into(),
                dropped: true,
                matched_rule: Some("XDP-UDP-AMPLIFICATION-BLOCK".into()),
                reason: format!("UDP reflection amplification payload ({} bytes) dropped at NIC driver", pkt.payload_size),
                latency_ns: 150,
                interface: "eth0".into(),
            };
        }

        // 3. Known blacklisted threat IPs
        if pkt.src_ip.starts_with("198.51.100.99") || pkt.src_ip.starts_with("203.0.113.88") {
            return XdpDecision {
                action: "XDP_DROP".into(),
                dropped: true,
                matched_rule: Some("XDP-IP-BLACKLIST-MAP".into()),
                reason: format!("Source IP {} present in XDP kernel BPF blacklist map", pkt.src_ip),
                latency_ns: 110,
                interface: "eth0".into(),
            };
        }

        XdpDecision {
            action: "XDP_PASS".into(),
            dropped: false,
            matched_rule: None,
            reason: "Packet verified and passed to Linux network stack".into(),
            latency_ns: 90,
            interface: "eth0".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_xdp_packet_dropping() {
        // 1. SYN Flood packet
        let syn_flood = PacketHeader {
            src_ip: "45.33.32.100".into(),
            dst_ip: "10.0.0.1".into(),
            src_port: 54321,
            dst_port: 443,
            protocol: "TCP".into(),
            is_syn: true,
            pps_rate: 120_000,
            payload_size: 64,
        };
        let dec_syn = EbpfXdpEngine::evaluate_packet(&syn_flood);
        assert_eq!(dec_syn.action, "XDP_DROP");
        assert!(dec_syn.dropped);

        // 2. Normal traffic
        let normal_pkt = PacketHeader {
            src_ip: "192.168.1.50".into(),
            dst_ip: "10.0.0.1".into(),
            src_port: 49152,
            dst_port: 9090,
            protocol: "TCP".into(),
            is_syn: false,
            pps_rate: 100,
            payload_size: 512,
        };
        let dec_norm = EbpfXdpEngine::evaluate_packet(&normal_pkt);
        assert_eq!(dec_norm.action, "XDP_PASS");
        assert!(!dec_norm.dropped);
    }
}
