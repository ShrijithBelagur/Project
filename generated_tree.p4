#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<32> FLOW_SLOTS = 65536;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  reserved;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
}

struct metadata_t {
    bit<8> class_id;

    bit<32> ip_a;
    bit<16> port_a;
    bit<32> ip_b;
    bit<16> port_b;
    bit<32> idx0;
    bit<32> tag;

    bit<1> valid0;
    bit<32> stored_tag0;
    bit<32> stored_last_ts;
    bit<16> stored_max_len;
    bit<16> stored_min_len;
    bit<32> stored_max_ipd;
    bit<32> stored_min_ipd;

    bit<8> ip_len;
    bit<16> total_len;
    bit<8> proto;
    bit<8> tos;
    bit<8> tcp_offset;
    bit<32> now_ts;
    
    bit<16> max_packet_len;
    bit<16> min_packet_len;

    bit<32> max_ipd;
    bit<32> min_ipd;
    bit<32> last_ipd;
}

parser MyParser(packet_in packet, out headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) { apply { } }

register<bit<1>>(65536) valid0_reg;
register<bit<32>>(65536) tag0_reg;
register<bit<32>>(65536) last_ts0_reg;
register<bit<16>>(65536) max_len0_reg;
register<bit<16>>(65536) min_len0_reg;
register<bit<32>>(65536) max_ipd0_reg;
register<bit<32>>(65536) min_ipd0_reg;


control MyIngress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action canonicalize() {
        if ((hdr.ipv4.srcAddr < hdr.ipv4.dstAddr) || ((hdr.ipv4.srcAddr == hdr.ipv4.dstAddr) && (hdr.tcp.srcPort <= hdr.tcp.dstPort))) {
            meta.ip_a = hdr.ipv4.srcAddr; meta.port_a = hdr.tcp.srcPort; meta.ip_b = hdr.ipv4.dstAddr; meta.port_b = hdr.tcp.dstPort;
        } else {
            meta.ip_a = hdr.ipv4.dstAddr; meta.port_a = hdr.tcp.dstPort; meta.ip_b = hdr.ipv4.srcAddr; meta.port_b = hdr.tcp.srcPort;
        }
    }
    action compute_hashes() {
        hash(meta.idx0, HashAlgorithm.crc16, 32w0, { hdr.ipv4.protocol, meta.ip_a, meta.port_a, meta.ip_b, meta.port_b }, FLOW_SLOTS);
        hash(meta.tag, HashAlgorithm.crc32, 32w0, { hdr.ipv4.protocol, meta.ip_a, meta.port_a, meta.ip_b, meta.port_b }, 32w4294967295);
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

    apply {
        meta.class_id = 0;

        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            canonicalize(); compute_hashes(); load_raw_features(); read_bank0(); update_bank0();  
        } 
        else {
            drop(); 
        }

        if (hdr.ipv4.isValid()) {
            // Generated root-to-leaf traversal.
            if (meta.max_packet_len <= 3082) {
                if (meta.max_packet_len <= 1541) {
                    if (hdr.ipv4.diffserv <= 44) {
                        if (meta.max_ipd <= 468) {
                            if (meta.max_packet_len <= 589) {
                                meta.class_id = 1;
                            } else {
                                meta.class_id = 0;
                            }
                        } else {
                            if (meta.max_ipd <= 1629) {
                                meta.class_id = 1;
                            } else {
                                meta.class_id = 1;
                            }
                        }
                    } else {
                        if (hdr.ipv4.totalLen <= 659) {
                            if (hdr.ipv4.totalLen <= 74) {
                                meta.class_id = 1;
                            } else {
                                meta.class_id = 2;
                            }
                        } else {
                            if (meta.max_packet_len <= 1153) {
                                meta.class_id = 2;
                            } else {
                                meta.class_id = 0;
                            }
                        }
                    }
                } else {
                    if (meta.max_packet_len <= 2937) {
                        if (meta.max_packet_len <= 2880) {
                            if (meta.max_packet_len <= 1622) {
                                meta.class_id = 0;
                            } else {
                                meta.class_id = 0;
                            }
                        } else {
                            if (meta.max_packet_len <= 2883) {
                                meta.class_id = 1;
                            } else {
                                meta.class_id = 0;
                            }
                        }
                    } else {
                        if (meta.max_ipd <= 2429) {
                            if (meta.max_packet_len <= 2978) {
                                meta.class_id = 0;
                            } else {
                                meta.class_id = 1;
                            }
                        } else {
                            if (hdr.ipv4.diffserv <= 44) {
                                meta.class_id = 1;
                            } else {
                                meta.class_id = 0;
                            }
                        }
                    }
                }
            } else {
                if (meta.max_packet_len <= 7310) {
                    if (meta.max_ipd <= 2013) {
                        if (meta.max_ipd <= 1358) {
                            if (meta.max_packet_len <= 7134) {
                                meta.class_id = 2;
                            } else {
                                meta.class_id = 2;
                            }
                        } else {
                            if (meta.max_ipd <= 1556) {
                                meta.class_id = 2;
                            } else {
                                meta.class_id = 2;
                            }
                        }
                    } else {
                        if (meta.max_packet_len <= 5878) {
                            if (meta.max_packet_len <= 5241) {
                                meta.class_id = 2;
                            } else {
                                meta.class_id = 2;
                            }
                        } else {
                            if (meta.max_ipd <= 2538) {
                                meta.class_id = 1;
                            } else {
                                meta.class_id = 2;
                            }
                        }
                    }
                } else {
                    if (meta.last_ipd <= 207) {
                        if (meta.max_packet_len <= 8820) {
                            if (meta.max_packet_len <= 7368) {
                                meta.class_id = 2;
                            } else {
                                meta.class_id = 2;
                            }
                        } else {
                            if (meta.max_packet_len <= 8887) {
                                meta.class_id = 1;
                            } else {
                                meta.class_id = 2;
                            }
                        }
                    } else {
                        if (hdr.ipv4.totalLen <= 1510) {
                            if (meta.last_ipd <= 1409) {
                                meta.class_id = 2;
                            } else {
                                meta.class_id = 2;
                            }
                        } else {
                            if (hdr.ipv4.totalLen <= 2987) {
                                meta.class_id = 1;
                            } else {
                                meta.class_id = 2;
                            }
                        }
                    }
                }
            }
        }

        if (meta.class_id == 0) {
            forward(1);
        } 
        else if (meta.class_id == 1) {
            forward(2);
        }
        else if (meta.class_id == 2){
            forward(3);
        } 
        else {
            drop();
        }
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { apply { } }

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) { apply { } }

control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
