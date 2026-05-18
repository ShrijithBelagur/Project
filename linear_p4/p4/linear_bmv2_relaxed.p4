#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8> PROTO_TCP = 6;
const bit<32> FLOW_SLOTS = 65536;

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

struct metadata_t {
    bit<32> ip_a; bit<16> port_a; bit<32> ip_b; bit<16> port_b; bit<32> idx0; bit<32> idx1; bit<32> tag;
    bit<1> valid0; bit<1> valid1; bit<32> stored_tag0; bit<32> stored_tag1; bit<32> stored_last_ts0; bit<32> stored_last_ts1;
    bit<32> stored_last_ts; bit<16> stored_max_len; bit<16> stored_min_len; bit<32> stored_max_ipd; bit<32> stored_min_ipd;
    bit<2> selected_bank;
    bit<32> now_ts; bit<8> ip_len; bit<16> total_len; bit<8> proto; bit<8> tos; bit<8> tcp_offset;
    bit<16> max_packet_len; bit<16> min_packet_len; bit<32> max_ipd; bit<32> min_ipd; bit<32> last_ipd;

    int<32> f0; int<32> f1; int<32> f2; int<32> f3; int<32> f4; int<32> f5; int<32> f6; int<32> f7; int<32> f8; int<32> f9;
    int<32> score0; int<32> score1; int<32> score2; int<32> best_score;
    bit<8> predicted_label;
    int<16> w16; int<32> r32;
}

register<bit<1>>(65536) valid0_reg; register<bit<32>>(65536) tag0_reg; register<bit<32>>(65536) last_ts0_reg;
register<bit<16>>(65536) max_len0_reg; register<bit<16>>(65536) min_len0_reg; register<bit<32>>(65536) max_ipd0_reg; register<bit<32>>(65536) min_ipd0_reg;
register<bit<1>>(65536) valid1_reg; register<bit<32>>(65536) tag1_reg; register<bit<32>>(65536) last_ts1_reg;
register<bit<16>>(65536) max_len1_reg; register<bit<16>>(65536) min_len1_reg; register<bit<32>>(65536) max_ipd1_reg; register<bit<32>>(65536) min_ipd1_reg;

register<int<16>>(30) lin_w_reg;
register<int<32>>(3) lin_b_reg;

parser MyParser(packet_in packet, out headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    state start { packet.extract(hdr.ethernet); transition select(hdr.ethernet.etherType) { TYPE_IPV4: parse_ipv4; default: accept; } }
    state parse_ipv4 { packet.extract(hdr.ipv4); transition select(hdr.ipv4.protocol) { PROTO_TCP: parse_tcp; default: accept; } }
    state parse_tcp { packet.extract(hdr.tcp); transition accept; }
}
control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) { apply {} }

control MyIngress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    action drop() { mark_to_drop(standard_metadata); }
    action canonicalize() {
        if ((hdr.ipv4.srcAddr < hdr.ipv4.dstAddr) || ((hdr.ipv4.srcAddr == hdr.ipv4.dstAddr) && (hdr.tcp.srcPort <= hdr.tcp.dstPort))) {
            meta.ip_a = hdr.ipv4.srcAddr; meta.port_a = hdr.tcp.srcPort; meta.ip_b = hdr.ipv4.dstAddr; meta.port_b = hdr.tcp.dstPort;
        } else {
            meta.ip_a = hdr.ipv4.dstAddr; meta.port_a = hdr.tcp.dstPort; meta.ip_b = hdr.ipv4.srcAddr; meta.port_b = hdr.tcp.srcPort;
        }
    }
    action compute_hashes() {
        hash(meta.idx0, HashAlgorithm.crc16, 32w0, { hdr.ipv4.protocol, meta.ip_a, meta.port_a, meta.ip_b, meta.port_b }, FLOW_SLOTS);
        hash(meta.idx1, HashAlgorithm.crc32, 32w0, { hdr.ipv4.protocol, meta.ip_a, meta.port_a, meta.ip_b, meta.port_b }, FLOW_SLOTS);
        hash(meta.tag, HashAlgorithm.crc32, 32w0, { hdr.ipv4.protocol, meta.ip_a, meta.port_a, meta.ip_b, meta.port_b }, 32w4294967295);
    }
    action load_raw_features() {
        meta.ip_len = (bit<8>) hdr.ipv4.ihl; meta.total_len = hdr.ipv4.totalLen + 16w14; meta.proto = hdr.ipv4.protocol;
        meta.tos = hdr.ipv4.diffserv; meta.tcp_offset = (bit<8>) hdr.tcp.dataOffset; meta.now_ts = (bit<32>) standard_metadata.ingress_global_timestamp;
    }
    action read_tags_and_age() {
        valid0_reg.read(meta.valid0, meta.idx0); tag0_reg.read(meta.stored_tag0, meta.idx0); last_ts0_reg.read(meta.stored_last_ts0, meta.idx0);
        valid1_reg.read(meta.valid1, meta.idx1); tag1_reg.read(meta.stored_tag1, meta.idx1); last_ts1_reg.read(meta.stored_last_ts1, meta.idx1);
    }
    action choose_bank() {
        if ((meta.valid0 == 1w1) && (meta.stored_tag0 == meta.tag)) { meta.selected_bank = 2w0; }
        else if ((meta.valid1 == 1w1) && (meta.stored_tag1 == meta.tag)) { meta.selected_bank = 2w1; }
        else if (meta.valid0 == 1w0) { meta.selected_bank = 2w0; }
        else if (meta.valid1 == 1w0) { meta.selected_bank = 2w1; }
        else if (meta.stored_last_ts0 <= meta.stored_last_ts1) { meta.selected_bank = 2w0; }
        else { meta.selected_bank = 2w1; }
    }
    action update_values_from_loaded_state() {
        meta.last_ipd = (meta.now_ts >= meta.stored_last_ts) ? (meta.now_ts - meta.stored_last_ts) : 32w0;
        meta.max_packet_len = meta.stored_max_len; if (meta.total_len > meta.max_packet_len) { meta.max_packet_len = meta.total_len; }
        meta.min_packet_len = meta.stored_min_len; if (meta.total_len < meta.min_packet_len) { meta.min_packet_len = meta.total_len; }
        meta.max_ipd = meta.stored_max_ipd; if (meta.last_ipd > meta.max_ipd) { meta.max_ipd = meta.last_ipd; }
        meta.min_ipd = meta.stored_min_ipd; if (meta.last_ipd < meta.min_ipd) { meta.min_ipd = meta.last_ipd; }
    }
    action cold_values() { meta.last_ipd = 32w0; meta.max_packet_len = meta.total_len; meta.min_packet_len = meta.total_len; meta.max_ipd = 32w0; meta.min_ipd = 32w0; }
    action use_bank0() {
        if ((meta.valid0 == 1w1) && (meta.stored_tag0 == meta.tag)) {
            last_ts0_reg.read(meta.stored_last_ts, meta.idx0); max_len0_reg.read(meta.stored_max_len, meta.idx0); min_len0_reg.read(meta.stored_min_len, meta.idx0);
            max_ipd0_reg.read(meta.stored_max_ipd, meta.idx0); min_ipd0_reg.read(meta.stored_min_ipd, meta.idx0); update_values_from_loaded_state();
        } else { cold_values(); }
        valid0_reg.write(meta.idx0, 1w1); tag0_reg.write(meta.idx0, meta.tag); last_ts0_reg.write(meta.idx0, meta.now_ts); max_len0_reg.write(meta.idx0, meta.max_packet_len); min_len0_reg.write(meta.idx0, meta.min_packet_len); max_ipd0_reg.write(meta.idx0, meta.max_ipd); min_ipd0_reg.write(meta.idx0, meta.min_ipd);
    }
    action use_bank1() {
        if ((meta.valid1 == 1w1) && (meta.stored_tag1 == meta.tag)) {
            last_ts1_reg.read(meta.stored_last_ts, meta.idx1); max_len1_reg.read(meta.stored_max_len, meta.idx1); min_len1_reg.read(meta.stored_min_len, meta.idx1);
            max_ipd1_reg.read(meta.stored_max_ipd, meta.idx1); min_ipd1_reg.read(meta.stored_min_ipd, meta.idx1); update_values_from_loaded_state();
        } else { cold_values(); }
        valid1_reg.write(meta.idx1, 1w1); tag1_reg.write(meta.idx1, meta.tag); last_ts1_reg.write(meta.idx1, meta.now_ts); max_len1_reg.write(meta.idx1, meta.max_packet_len); min_len1_reg.write(meta.idx1, meta.min_packet_len); max_ipd1_reg.write(meta.idx1, meta.max_ipd); min_ipd1_reg.write(meta.idx1, meta.min_ipd);
    }

    action set_class_port(bit<9> port) { standard_metadata.egress_spec = port; }
    table class_fwd { key = { meta.predicted_label: exact; } actions = { set_class_port; NoAction; } size = 8; default_action = NoAction(); }

    action prepare_linear_features() {
        meta.f0 = (int<32>)(bit<32>)meta.ip_len; meta.f1 = (int<32>)(bit<32>)meta.total_len; meta.f2 = (int<32>)(bit<32>)meta.proto; meta.f3 = (int<32>)(bit<32>)meta.tos; meta.f4 = (int<32>)(bit<32>)meta.tcp_offset; meta.f5 = (int<32>)(bit<32>)meta.max_packet_len; meta.f6 = (int<32>)(bit<32>)meta.min_packet_len; meta.f7 = (int<32>)(bit<32>)meta.max_ipd; meta.f8 = (int<32>)(bit<32>)meta.min_ipd; meta.f9 = (int<32>)(bit<32>)meta.last_ipd;
    }
    action mul_add(in int<16> w, in int<32> x, inout int<32> acc) { acc = acc + (((int<32>)w) * x); }
    action classify_linear_runtime() {
        lin_b_reg.read(meta.r32, 0); meta.score0 = meta.r32;
        lin_w_reg.read(meta.w16, 0); mul_add(meta.w16, meta.f0, meta.score0); lin_w_reg.read(meta.w16, 1); mul_add(meta.w16, meta.f1, meta.score0); lin_w_reg.read(meta.w16, 2); mul_add(meta.w16, meta.f2, meta.score0); lin_w_reg.read(meta.w16, 3); mul_add(meta.w16, meta.f3, meta.score0); lin_w_reg.read(meta.w16, 4); mul_add(meta.w16, meta.f4, meta.score0); lin_w_reg.read(meta.w16, 5); mul_add(meta.w16, meta.f5, meta.score0); lin_w_reg.read(meta.w16, 6); mul_add(meta.w16, meta.f6, meta.score0); lin_w_reg.read(meta.w16, 7); mul_add(meta.w16, meta.f7, meta.score0); lin_w_reg.read(meta.w16, 8); mul_add(meta.w16, meta.f8, meta.score0); lin_w_reg.read(meta.w16, 9); mul_add(meta.w16, meta.f9, meta.score0);
        lin_b_reg.read(meta.r32, 1); meta.score1 = meta.r32;
        lin_w_reg.read(meta.w16, 10); mul_add(meta.w16, meta.f0, meta.score1); lin_w_reg.read(meta.w16, 11); mul_add(meta.w16, meta.f1, meta.score1); lin_w_reg.read(meta.w16, 12); mul_add(meta.w16, meta.f2, meta.score1); lin_w_reg.read(meta.w16, 13); mul_add(meta.w16, meta.f3, meta.score1); lin_w_reg.read(meta.w16, 14); mul_add(meta.w16, meta.f4, meta.score1); lin_w_reg.read(meta.w16, 15); mul_add(meta.w16, meta.f5, meta.score1); lin_w_reg.read(meta.w16, 16); mul_add(meta.w16, meta.f6, meta.score1); lin_w_reg.read(meta.w16, 17); mul_add(meta.w16, meta.f7, meta.score1); lin_w_reg.read(meta.w16, 18); mul_add(meta.w16, meta.f8, meta.score1); lin_w_reg.read(meta.w16, 19); mul_add(meta.w16, meta.f9, meta.score1);
        lin_b_reg.read(meta.r32, 2); meta.score2 = meta.r32;
        lin_w_reg.read(meta.w16, 20); mul_add(meta.w16, meta.f0, meta.score2); lin_w_reg.read(meta.w16, 21); mul_add(meta.w16, meta.f1, meta.score2); lin_w_reg.read(meta.w16, 22); mul_add(meta.w16, meta.f2, meta.score2); lin_w_reg.read(meta.w16, 23); mul_add(meta.w16, meta.f3, meta.score2); lin_w_reg.read(meta.w16, 24); mul_add(meta.w16, meta.f4, meta.score2); lin_w_reg.read(meta.w16, 25); mul_add(meta.w16, meta.f5, meta.score2); lin_w_reg.read(meta.w16, 26); mul_add(meta.w16, meta.f6, meta.score2); lin_w_reg.read(meta.w16, 27); mul_add(meta.w16, meta.f7, meta.score2); lin_w_reg.read(meta.w16, 28); mul_add(meta.w16, meta.f8, meta.score2); lin_w_reg.read(meta.w16, 29); mul_add(meta.w16, meta.f9, meta.score2);
        meta.best_score = meta.score0; meta.predicted_label = 8w0; if (meta.score1 > meta.best_score) { meta.best_score = meta.score1; meta.predicted_label = 8w1; } if (meta.score2 > meta.best_score) { meta.best_score = meta.score2; meta.predicted_label = 8w2; }
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            canonicalize(); compute_hashes(); load_raw_features(); read_tags_and_age(); choose_bank();
            if (meta.selected_bank == 2w0) { use_bank0(); } else { use_bank1(); }
            prepare_linear_features(); classify_linear_runtime(); class_fwd.apply();
        } else { drop(); }
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { apply {} }
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) { apply {} }
control MyDeparser(packet_out packet, in headers_t hdr) { apply { packet.emit(hdr.ethernet); packet.emit(hdr.ipv4); packet.emit(hdr.tcp); } }
V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
