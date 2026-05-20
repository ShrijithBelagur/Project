// L2 forwarding baseline for the PeerRush benchmark topology.
//
// Parses Ethernet + IPv4 + TCP exactly like the classifier pipelines, then
// forwards purely by destination MAC. No flow state, no model evaluation,
// no math. The sender already stamps the correct dst MAC for each packet's
// true class, so this acts as a "perfect classifier" — accuracy approaches
// 100% and any drop / latency / throughput difference vs the classifier
// pipelines reflects pure model-evaluation cost in BMv2, not parser cost
// or routing logic.

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  PROTO_TCP = 6;

header ethernet_t { bit<48> dstAddr; bit<48> srcAddr; bit<16> etherType; }
header ipv4_t {
    bit<4> version; bit<4> ihl; bit<8> diffserv; bit<16> totalLen; bit<16> identification;
    bit<3> flags; bit<13> fragOffset; bit<8> ttl; bit<8> protocol; bit<16> hdrChecksum;
    bit<32> srcAddr; bit<32> dstAddr;
}
header tcp_t {
    bit<16> srcPort; bit<16> dstPort; bit<32> seqNo; bit<32> ackNo; bit<4> dataOffset;
    bit<3> res; bit<3> ecn; bit<6> ctrl; bit<16> window; bit<16> checksum; bit<16> urgentPtr;
}

struct headers_t { ethernet_t ethernet; ipv4_t ipv4; tcp_t tcp; }
struct metadata_t { }

parser MyParser(packet_in packet, out headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    state start { packet.extract(hdr.ethernet); transition select(hdr.ethernet.etherType) { TYPE_IPV4: parse_ipv4; default: accept; } }
    state parse_ipv4 { packet.extract(hdr.ipv4); transition select(hdr.ipv4.protocol) { PROTO_TCP: parse_tcp; default: accept; } }
    state parse_tcp { packet.extract(hdr.tcp); transition accept; }
}

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) { apply {} }

control MyIngress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    action drop() { mark_to_drop(standard_metadata); }
    action forward(bit<9> port) { standard_metadata.egress_spec = port; }

    table mac_to_port {
        key = { hdr.ethernet.dstAddr: exact; }
        actions = { forward; drop; NoAction; }
        size = 16;
        default_action = drop();
        const entries = {
            0x020000000101 : forward(9w1);
            0x020000000201 : forward(9w2);
            0x020000000301 : forward(9w3);
        }
    }

    apply {
        if (hdr.ethernet.isValid()) {
            mac_to_port.apply();
        } else {
            drop();
        }
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { apply {} }
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) { apply {} }
control MyDeparser(packet_out packet, in headers_t hdr) { apply { packet.emit(hdr.ethernet); packet.emit(hdr.ipv4); packet.emit(hdr.tcp); } }
V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
