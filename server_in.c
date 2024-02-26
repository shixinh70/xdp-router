#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "router.h"
#define MAX_ENTRY 2000
char _license[] SEC("license") = "GPL";

struct map_key_t {
        __u32 src_ip;
        __u32 dst_ip;
        __u16 src_port;
        __u16 dst_port;
};

struct map_val_t {
        __u32 ts_val_s;
        __u32 delta;	
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRY);
        __type(key, struct map_key_t);
        __type(value, struct map_val_t);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack_map SEC(".maps");

// main router logic
SEC("prog") int xdp_router(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor cur;
    struct ethhdr* eth;
    struct iphdr* ip;
    struct tcphdr* tcp;

    cur.pos = data;
    int ether_proto ;
    ether_proto = parse_ethhdr(&cur,data_end,&eth);
    if(ether_proto == -1) return XDP_DROP;
    
    if (bpf_htons(ether_proto) == ETH_P_IP) {

        int ip_proto = parse_iphdr(&cur, data_end, &ip);
        if(ip_proto == -1) return XDP_DROP;
        if(ip_proto == IPPROTO_TCP){
            DEBUG_PRINT("SERVER_IN: TCP packet (with options) ingress\n");
        
            int tcphdr_len = parse_tcphdr(&cur, data_end, &tcp);
            if(tcphdr_len == -1) return XDP_DROP;
            if(tcphdr_len >= 32){ // Timestamp need 12 byte (Nop Nop timestamp)
            struct tcp_opt_ts* ts;
            DEBUG_PRINT("SERVER_IN: TCP packet (with options) ingress\n");
            // This parse timestamp may can be optimize
            // Switch agent have parse the timestamp so can put the ts type
            // in some un-used header field.
                if(tcp->ack && (!tcp->syn)){
                    int opt_ts_offset = parse_ack_timestamp(&cur,data_end,&ts);
                    if(opt_ts_offset == -1) return XDP_DROP;   
                    __u32 tsecr = bpf_ntohl(ts->tsecr);
                    void* tcp_header_end = (void*)tcp + (tcp->doff*4);
                    if(tcp_header_end > data_end) return XDP_DROP;
                    // Ack packet which TS == TS_START and no payload.
                    // Insert new connection 
                    if (tsecr == TS_START && (tcp_header_end == data_end)){
                        DEBUG_PRINT("SERVER_IN: Ack packet tsecr == TS_START, and NO payload, Create conntrack--\n");
                        struct map_key_t key = {
                            .src_ip = ip->saddr,
                            .dst_ip = ip->daddr,
                            .src_port = tcp->source,
                            .dst_port = tcp->dest
                        };
                        // struct map_val_t* val = bpf_map_lookup_elem (&conntrack_map, &key);
                        // if(val == NULL) DEBUG_PRINT("No connection in conntrack_map, create new one\n");
                        // else DEBUG_PRINT("Find connection in conntrack_map, update old one\n");
                        // Update and Create val are same function;
                        // Then store the ack for compute ack delta.
                        struct map_val_t val = {.delta = tcp->ack_seq,
                                                .ts_val_s = ts->tsval};
                                         
                        bpf_map_update_elem(&conntrack_map, &key, &val, BPF_ANY);

                        // Change ACK packet to SYN packet (seq = seq -1 , ack = 0, tsecr = 0);
                        // Store some message for compute TCP csum
                        __u32 old_tcp_seq = tcp->seq;
                        __u32 old_tcp_ack = tcp->ack_seq;
                        __u64 tcp_csum = tcp->check;
                        __u32 old_tcp_tsecr = ts->tsecr;
                        __u32* ptr ; 
                        ptr = ((void*)tcp) + 12;
                       

                        // if(((void*)tcp) + 12 > data_end) return XDP_DROP;
                        // DEBUG_PRINT("ffffffff\n");

                        if((void*)ptr + 4 > data_end) return XDP_DROP;
                       
                        __u32 tcp_old_flag = *ptr;

                        tcp->ack = 0;tcp->syn = 1;
                        __u32 tcp_new_flag = *ptr;

                        tcp->seq -= bpf_htonl(1);
                        tcp->ack_seq = 0;
                        ts->tsecr = 0;
                        
                        //Compute TCP checksum
                        tcp_csum = bpf_csum_diff(&tcp_old_flag, 4, &tcp_new_flag, 4, ~tcp_csum);
                        tcp_csum = bpf_csum_diff(&old_tcp_seq, 4, &tcp->seq, 4, tcp_csum);
                        tcp_csum = bpf_csum_diff(&old_tcp_ack, 4, 0, 0, tcp_csum);
                        tcp_csum = bpf_csum_diff(&old_tcp_tsecr, 4, 0, 0, tcp_csum);
                        tcp->check = csum_fold_helper_64(tcp_csum);

                    }
                    else{
                        DEBUG_PRINT("SERVER_IN: Ack packet tsecr != TS_START, and NO payload\n \
                                    \n");
                    }
                }
                
            
            }
            else{
                DEBUG_PRINT("SERVER_IN: No options TCP packet ingress, Foward\n");

            }
        } 
    }
    return XDP_PASS;
}
