#include <core.p4>
#include <v1model.p4>

// Constrained dataplane BNN profile:
// - P4-deployable 10x8x3 hybrid quantized BNN.
// - Single CRC16-indexed tagged flow-state bank.
// - Deliberately small 4096-slot state table to emulate tighter switch SRAM.
// - 16-bit fingerprint tag, so both index pressure and tag aliasing are visible.
// - Ternary weights, binary hidden activations, integer-only inference.

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8> PROTO_TCP = 6;
const bit<32> CONSTRAINED_FLOW_SLOTS = 32w4096;
const bit<16> CONSTRAINED_TAG_SPACE = 16w65535;

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
    bit<32> ip_a; bit<16> port_a; bit<32> ip_b; bit<16> port_b;
    bit<32> idx0; bit<16> tag;
    bit<1> valid0; bit<16> stored_tag0; bit<32> stored_last_ts;
    bit<16> stored_max_len; bit<16> stored_min_len; bit<32> stored_max_ipd; bit<32> stored_min_ipd;
    bit<32> now_ts;
    bit<8> ip_len; bit<16> total_len; bit<8> proto; bit<8> tos; bit<8> tcp_offset;
    bit<16> max_packet_len; bit<16> min_packet_len; bit<32> max_ipd; bit<32> min_ipd; bit<32> last_ipd;

    int<32> f0; int<32> f1; int<32> f2; int<32> f3; int<32> f4; int<32> f5; int<32> f6; int<32> f7; int<32> f8; int<32> f9;
    int<32> acc0; int<32> acc1; int<32> acc2; int<32> acc3; int<32> acc4; int<32> acc5; int<32> acc6; int<32> acc7;
    int<32> h0; int<32> h1; int<32> h2; int<32> h3; int<32> h4; int<32> h5; int<32> h6; int<32> h7;
    int<32> score0; int<32> score1; int<32> score2; int<32> best_score;
    bit<8> predicted_label;
    bit<2> w2; int<16> r16;
}

register<bit<1>>(4096) valid0_reg;
register<bit<16>>(4096) tag0_reg;
register<bit<32>>(4096) last_ts0_reg;
register<bit<16>>(4096) max_len0_reg;
register<bit<16>>(4096) min_len0_reg;
register<bit<32>>(4096) max_ipd0_reg;
register<bit<32>>(4096) min_ipd0_reg;

register<bit<2>>(80) nn_w1_reg;
register<int<16>>(8) nn_th1_reg;
register<int<16>>(8) nn_b1_reg;
register<bit<2>>(24) nn_w2_reg;
register<int<16>>(3) nn_b2_reg;

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
        hash(meta.idx0, HashAlgorithm.crc16, 32w0, { hdr.ipv4.protocol, meta.ip_a, meta.port_a, meta.ip_b, meta.port_b }, CONSTRAINED_FLOW_SLOTS);
        hash(meta.tag, HashAlgorithm.crc16, 32w0, { hdr.ipv4.protocol, meta.ip_a, meta.port_a, meta.ip_b, meta.port_b }, CONSTRAINED_TAG_SPACE);
    }
    action load_raw_features() {
        meta.ip_len = (bit<8>) hdr.ipv4.ihl;
        meta.total_len = hdr.ipv4.totalLen + 16w14;
        meta.proto = hdr.ipv4.protocol;
        meta.tos = hdr.ipv4.diffserv;
        meta.tcp_offset = (bit<8>) hdr.tcp.dataOffset;
        meta.now_ts = (bit<32>) standard_metadata.ingress_global_timestamp;
    }
    action read_bank0() {
        valid0_reg.read(meta.valid0, meta.idx0);
        tag0_reg.read(meta.stored_tag0, meta.idx0);
        last_ts0_reg.read(meta.stored_last_ts, meta.idx0);
        max_len0_reg.read(meta.stored_max_len, meta.idx0);
        min_len0_reg.read(meta.stored_min_len, meta.idx0);
        max_ipd0_reg.read(meta.stored_max_ipd, meta.idx0);
        min_ipd0_reg.read(meta.stored_min_ipd, meta.idx0);
    }
    action update_bank0() {
        if ((meta.valid0 == 1w1) && (meta.stored_tag0 == meta.tag)) {
            meta.last_ipd = (meta.now_ts >= meta.stored_last_ts) ? (meta.now_ts - meta.stored_last_ts) : 32w0;
            meta.max_packet_len = meta.stored_max_len; if (meta.total_len > meta.max_packet_len) { meta.max_packet_len = meta.total_len; }
            meta.min_packet_len = meta.stored_min_len; if (meta.total_len < meta.min_packet_len) { meta.min_packet_len = meta.total_len; }
            meta.max_ipd = meta.stored_max_ipd; if (meta.last_ipd > meta.max_ipd) { meta.max_ipd = meta.last_ipd; }
            meta.min_ipd = meta.stored_min_ipd; if (meta.last_ipd < meta.min_ipd) { meta.min_ipd = meta.last_ipd; }
        } else {
            meta.last_ipd = 32w0; meta.max_packet_len = meta.total_len; meta.min_packet_len = meta.total_len; meta.max_ipd = 32w0; meta.min_ipd = 32w0;
        }
        valid0_reg.write(meta.idx0, 1w1); tag0_reg.write(meta.idx0, meta.tag); last_ts0_reg.write(meta.idx0, meta.now_ts);
        max_len0_reg.write(meta.idx0, meta.max_packet_len); min_len0_reg.write(meta.idx0, meta.min_packet_len);
        max_ipd0_reg.write(meta.idx0, meta.max_ipd); min_ipd0_reg.write(meta.idx0, meta.min_ipd);
    }

    action set_class_port(bit<9> port) { standard_metadata.egress_spec = port; }
    table class_fwd { key = { meta.predicted_label: exact; } actions = { set_class_port; NoAction; } size = 8; default_action = NoAction(); }

    action ternary_add(in bit<2> w, in int<32> x, inout int<32> acc) { if (w == 2w2) { acc = acc + x; } else if (w == 2w0) { acc = acc - x; } }
    action prepare_nn_features() {
        meta.f0 = (int<32>)(bit<32>)meta.ip_len; meta.f1 = (int<32>)(bit<32>)meta.total_len; meta.f2 = (int<32>)(bit<32>)meta.proto;
        meta.f3 = (int<32>)(bit<32>)meta.tos; meta.f4 = (int<32>)(bit<32>)meta.tcp_offset; meta.f5 = (int<32>)(bit<32>)meta.max_packet_len;
        meta.f6 = (int<32>)(bit<32>)meta.min_packet_len; meta.f7 = (int<32>)(bit<32>)meta.max_ipd; meta.f8 = (int<32>)(bit<32>)meta.min_ipd;
        meta.f9 = (int<32>)(bit<32>)meta.last_ipd;
    }
    action classify_bnn_runtime() {
        nn_b1_reg.read(meta.r16, 0); meta.acc0 = (int<32>)meta.r16;
        nn_w1_reg.read(meta.w2, 0); ternary_add(meta.w2, meta.f0, meta.acc0); nn_w1_reg.read(meta.w2, 1); ternary_add(meta.w2, meta.f1, meta.acc0); nn_w1_reg.read(meta.w2, 2); ternary_add(meta.w2, meta.f2, meta.acc0); nn_w1_reg.read(meta.w2, 3); ternary_add(meta.w2, meta.f3, meta.acc0); nn_w1_reg.read(meta.w2, 4); ternary_add(meta.w2, meta.f4, meta.acc0); nn_w1_reg.read(meta.w2, 5); ternary_add(meta.w2, meta.f5, meta.acc0); nn_w1_reg.read(meta.w2, 6); ternary_add(meta.w2, meta.f6, meta.acc0); nn_w1_reg.read(meta.w2, 7); ternary_add(meta.w2, meta.f7, meta.acc0); nn_w1_reg.read(meta.w2, 8); ternary_add(meta.w2, meta.f8, meta.acc0); nn_w1_reg.read(meta.w2, 9); ternary_add(meta.w2, meta.f9, meta.acc0); nn_th1_reg.read(meta.r16, 0); meta.h0 = (meta.acc0 > (int<32>)meta.r16) ? 32s1 : 32s0;
        nn_b1_reg.read(meta.r16, 1); meta.acc1 = (int<32>)meta.r16;
        nn_w1_reg.read(meta.w2, 10); ternary_add(meta.w2, meta.f0, meta.acc1); nn_w1_reg.read(meta.w2, 11); ternary_add(meta.w2, meta.f1, meta.acc1); nn_w1_reg.read(meta.w2, 12); ternary_add(meta.w2, meta.f2, meta.acc1); nn_w1_reg.read(meta.w2, 13); ternary_add(meta.w2, meta.f3, meta.acc1); nn_w1_reg.read(meta.w2, 14); ternary_add(meta.w2, meta.f4, meta.acc1); nn_w1_reg.read(meta.w2, 15); ternary_add(meta.w2, meta.f5, meta.acc1); nn_w1_reg.read(meta.w2, 16); ternary_add(meta.w2, meta.f6, meta.acc1); nn_w1_reg.read(meta.w2, 17); ternary_add(meta.w2, meta.f7, meta.acc1); nn_w1_reg.read(meta.w2, 18); ternary_add(meta.w2, meta.f8, meta.acc1); nn_w1_reg.read(meta.w2, 19); ternary_add(meta.w2, meta.f9, meta.acc1); nn_th1_reg.read(meta.r16, 1); meta.h1 = (meta.acc1 > (int<32>)meta.r16) ? 32s1 : 32s0;
        nn_b1_reg.read(meta.r16, 2); meta.acc2 = (int<32>)meta.r16;
        nn_w1_reg.read(meta.w2, 20); ternary_add(meta.w2, meta.f0, meta.acc2); nn_w1_reg.read(meta.w2, 21); ternary_add(meta.w2, meta.f1, meta.acc2); nn_w1_reg.read(meta.w2, 22); ternary_add(meta.w2, meta.f2, meta.acc2); nn_w1_reg.read(meta.w2, 23); ternary_add(meta.w2, meta.f3, meta.acc2); nn_w1_reg.read(meta.w2, 24); ternary_add(meta.w2, meta.f4, meta.acc2); nn_w1_reg.read(meta.w2, 25); ternary_add(meta.w2, meta.f5, meta.acc2); nn_w1_reg.read(meta.w2, 26); ternary_add(meta.w2, meta.f6, meta.acc2); nn_w1_reg.read(meta.w2, 27); ternary_add(meta.w2, meta.f7, meta.acc2); nn_w1_reg.read(meta.w2, 28); ternary_add(meta.w2, meta.f8, meta.acc2); nn_w1_reg.read(meta.w2, 29); ternary_add(meta.w2, meta.f9, meta.acc2); nn_th1_reg.read(meta.r16, 2); meta.h2 = (meta.acc2 > (int<32>)meta.r16) ? 32s1 : 32s0;
        nn_b1_reg.read(meta.r16, 3); meta.acc3 = (int<32>)meta.r16;
        nn_w1_reg.read(meta.w2, 30); ternary_add(meta.w2, meta.f0, meta.acc3); nn_w1_reg.read(meta.w2, 31); ternary_add(meta.w2, meta.f1, meta.acc3); nn_w1_reg.read(meta.w2, 32); ternary_add(meta.w2, meta.f2, meta.acc3); nn_w1_reg.read(meta.w2, 33); ternary_add(meta.w2, meta.f3, meta.acc3); nn_w1_reg.read(meta.w2, 34); ternary_add(meta.w2, meta.f4, meta.acc3); nn_w1_reg.read(meta.w2, 35); ternary_add(meta.w2, meta.f5, meta.acc3); nn_w1_reg.read(meta.w2, 36); ternary_add(meta.w2, meta.f6, meta.acc3); nn_w1_reg.read(meta.w2, 37); ternary_add(meta.w2, meta.f7, meta.acc3); nn_w1_reg.read(meta.w2, 38); ternary_add(meta.w2, meta.f8, meta.acc3); nn_w1_reg.read(meta.w2, 39); ternary_add(meta.w2, meta.f9, meta.acc3); nn_th1_reg.read(meta.r16, 3); meta.h3 = (meta.acc3 > (int<32>)meta.r16) ? 32s1 : 32s0;
        nn_b1_reg.read(meta.r16, 4); meta.acc4 = (int<32>)meta.r16;
        nn_w1_reg.read(meta.w2, 40); ternary_add(meta.w2, meta.f0, meta.acc4); nn_w1_reg.read(meta.w2, 41); ternary_add(meta.w2, meta.f1, meta.acc4); nn_w1_reg.read(meta.w2, 42); ternary_add(meta.w2, meta.f2, meta.acc4); nn_w1_reg.read(meta.w2, 43); ternary_add(meta.w2, meta.f3, meta.acc4); nn_w1_reg.read(meta.w2, 44); ternary_add(meta.w2, meta.f4, meta.acc4); nn_w1_reg.read(meta.w2, 45); ternary_add(meta.w2, meta.f5, meta.acc4); nn_w1_reg.read(meta.w2, 46); ternary_add(meta.w2, meta.f6, meta.acc4); nn_w1_reg.read(meta.w2, 47); ternary_add(meta.w2, meta.f7, meta.acc4); nn_w1_reg.read(meta.w2, 48); ternary_add(meta.w2, meta.f8, meta.acc4); nn_w1_reg.read(meta.w2, 49); ternary_add(meta.w2, meta.f9, meta.acc4); nn_th1_reg.read(meta.r16, 4); meta.h4 = (meta.acc4 > (int<32>)meta.r16) ? 32s1 : 32s0;
        nn_b1_reg.read(meta.r16, 5); meta.acc5 = (int<32>)meta.r16;
        nn_w1_reg.read(meta.w2, 50); ternary_add(meta.w2, meta.f0, meta.acc5); nn_w1_reg.read(meta.w2, 51); ternary_add(meta.w2, meta.f1, meta.acc5); nn_w1_reg.read(meta.w2, 52); ternary_add(meta.w2, meta.f2, meta.acc5); nn_w1_reg.read(meta.w2, 53); ternary_add(meta.w2, meta.f3, meta.acc5); nn_w1_reg.read(meta.w2, 54); ternary_add(meta.w2, meta.f4, meta.acc5); nn_w1_reg.read(meta.w2, 55); ternary_add(meta.w2, meta.f5, meta.acc5); nn_w1_reg.read(meta.w2, 56); ternary_add(meta.w2, meta.f6, meta.acc5); nn_w1_reg.read(meta.w2, 57); ternary_add(meta.w2, meta.f7, meta.acc5); nn_w1_reg.read(meta.w2, 58); ternary_add(meta.w2, meta.f8, meta.acc5); nn_w1_reg.read(meta.w2, 59); ternary_add(meta.w2, meta.f9, meta.acc5); nn_th1_reg.read(meta.r16, 5); meta.h5 = (meta.acc5 > (int<32>)meta.r16) ? 32s1 : 32s0;
        nn_b1_reg.read(meta.r16, 6); meta.acc6 = (int<32>)meta.r16;
        nn_w1_reg.read(meta.w2, 60); ternary_add(meta.w2, meta.f0, meta.acc6); nn_w1_reg.read(meta.w2, 61); ternary_add(meta.w2, meta.f1, meta.acc6); nn_w1_reg.read(meta.w2, 62); ternary_add(meta.w2, meta.f2, meta.acc6); nn_w1_reg.read(meta.w2, 63); ternary_add(meta.w2, meta.f3, meta.acc6); nn_w1_reg.read(meta.w2, 64); ternary_add(meta.w2, meta.f4, meta.acc6); nn_w1_reg.read(meta.w2, 65); ternary_add(meta.w2, meta.f5, meta.acc6); nn_w1_reg.read(meta.w2, 66); ternary_add(meta.w2, meta.f6, meta.acc6); nn_w1_reg.read(meta.w2, 67); ternary_add(meta.w2, meta.f7, meta.acc6); nn_w1_reg.read(meta.w2, 68); ternary_add(meta.w2, meta.f8, meta.acc6); nn_w1_reg.read(meta.w2, 69); ternary_add(meta.w2, meta.f9, meta.acc6); nn_th1_reg.read(meta.r16, 6); meta.h6 = (meta.acc6 > (int<32>)meta.r16) ? 32s1 : 32s0;
        nn_b1_reg.read(meta.r16, 7); meta.acc7 = (int<32>)meta.r16;
        nn_w1_reg.read(meta.w2, 70); ternary_add(meta.w2, meta.f0, meta.acc7); nn_w1_reg.read(meta.w2, 71); ternary_add(meta.w2, meta.f1, meta.acc7); nn_w1_reg.read(meta.w2, 72); ternary_add(meta.w2, meta.f2, meta.acc7); nn_w1_reg.read(meta.w2, 73); ternary_add(meta.w2, meta.f3, meta.acc7); nn_w1_reg.read(meta.w2, 74); ternary_add(meta.w2, meta.f4, meta.acc7); nn_w1_reg.read(meta.w2, 75); ternary_add(meta.w2, meta.f5, meta.acc7); nn_w1_reg.read(meta.w2, 76); ternary_add(meta.w2, meta.f6, meta.acc7); nn_w1_reg.read(meta.w2, 77); ternary_add(meta.w2, meta.f7, meta.acc7); nn_w1_reg.read(meta.w2, 78); ternary_add(meta.w2, meta.f8, meta.acc7); nn_w1_reg.read(meta.w2, 79); ternary_add(meta.w2, meta.f9, meta.acc7); nn_th1_reg.read(meta.r16, 7); meta.h7 = (meta.acc7 > (int<32>)meta.r16) ? 32s1 : 32s0;

        nn_b2_reg.read(meta.r16, 0); meta.score0 = (int<32>)meta.r16;
        nn_w2_reg.read(meta.w2, 0); ternary_add(meta.w2, meta.h0, meta.score0); nn_w2_reg.read(meta.w2, 1); ternary_add(meta.w2, meta.h1, meta.score0); nn_w2_reg.read(meta.w2, 2); ternary_add(meta.w2, meta.h2, meta.score0); nn_w2_reg.read(meta.w2, 3); ternary_add(meta.w2, meta.h3, meta.score0); nn_w2_reg.read(meta.w2, 4); ternary_add(meta.w2, meta.h4, meta.score0); nn_w2_reg.read(meta.w2, 5); ternary_add(meta.w2, meta.h5, meta.score0); nn_w2_reg.read(meta.w2, 6); ternary_add(meta.w2, meta.h6, meta.score0); nn_w2_reg.read(meta.w2, 7); ternary_add(meta.w2, meta.h7, meta.score0);
        nn_b2_reg.read(meta.r16, 1); meta.score1 = (int<32>)meta.r16;
        nn_w2_reg.read(meta.w2, 8); ternary_add(meta.w2, meta.h0, meta.score1); nn_w2_reg.read(meta.w2, 9); ternary_add(meta.w2, meta.h1, meta.score1); nn_w2_reg.read(meta.w2, 10); ternary_add(meta.w2, meta.h2, meta.score1); nn_w2_reg.read(meta.w2, 11); ternary_add(meta.w2, meta.h3, meta.score1); nn_w2_reg.read(meta.w2, 12); ternary_add(meta.w2, meta.h4, meta.score1); nn_w2_reg.read(meta.w2, 13); ternary_add(meta.w2, meta.h5, meta.score1); nn_w2_reg.read(meta.w2, 14); ternary_add(meta.w2, meta.h6, meta.score1); nn_w2_reg.read(meta.w2, 15); ternary_add(meta.w2, meta.h7, meta.score1);
        nn_b2_reg.read(meta.r16, 2); meta.score2 = (int<32>)meta.r16;
        nn_w2_reg.read(meta.w2, 16); ternary_add(meta.w2, meta.h0, meta.score2); nn_w2_reg.read(meta.w2, 17); ternary_add(meta.w2, meta.h1, meta.score2); nn_w2_reg.read(meta.w2, 18); ternary_add(meta.w2, meta.h2, meta.score2); nn_w2_reg.read(meta.w2, 19); ternary_add(meta.w2, meta.h3, meta.score2); nn_w2_reg.read(meta.w2, 20); ternary_add(meta.w2, meta.h4, meta.score2); nn_w2_reg.read(meta.w2, 21); ternary_add(meta.w2, meta.h5, meta.score2); nn_w2_reg.read(meta.w2, 22); ternary_add(meta.w2, meta.h6, meta.score2); nn_w2_reg.read(meta.w2, 23); ternary_add(meta.w2, meta.h7, meta.score2);

        meta.best_score = meta.score0; meta.predicted_label = 8w0;
        if (meta.score1 > meta.best_score) { meta.best_score = meta.score1; meta.predicted_label = 8w1; }
        if (meta.score2 > meta.best_score) { meta.best_score = meta.score2; meta.predicted_label = 8w2; }
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            canonicalize(); compute_hashes(); load_raw_features(); read_bank0(); update_bank0();
            prepare_nn_features(); classify_bnn_runtime(); class_fwd.apply();
        } else { drop(); }
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { apply {} }
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) { apply {} }
control MyDeparser(packet_out packet, in headers_t hdr) { apply { packet.emit(hdr.ethernet); packet.emit(hdr.ipv4); packet.emit(hdr.tcp); } }
V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
