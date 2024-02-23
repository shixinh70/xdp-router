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

char _license[] SEC("license") = "GPL";



// helper: decr ttl by 1 for IP and IPv6


// main router logic
SEC("prog") int xdp_router(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor cur;
    struct ethhdr* eth;
    struct iphdr* ip;
    struct tcphdr* tcp;
    struct bpf_fib_lookup fib_params = {};
    long rc;
    
    cur.pos = data;
    int ether_proto ;
    ether_proto = parse_ethhdr(&cur,data_end,&eth);
    if(ether_proto == -1) return XDP_DROP;
    
    if (bpf_htons(ether_proto) == ETH_P_IP) {
        int ip_proto = parse_iphdr(&cur, data_end, &ip);
        if(ip_proto == -1) return XDP_DROP;
        if(ip_proto == IPPROTO_TCP){
            int tcphdr_len = parse_tcphdr(&cur, data_end, &tcp);
            if(tcphdr_len == -1) return XDP_DROP;

            if(tcphdr_len >= 32){ // Timestamp need 12 byte (Nop Nop timestamp)
            DEBUG_PRINT("TCP packet (with options) ingress  , Foward\n");
                    //DEBUG_PRINT ("Packet with option ingress\n");
                    struct tcp_opt_ts* ts;
                    __u32 rx_tsval = 0;
                    int opt_ts_offset = parse_ack_timestamp(&cur,data_end,&ts); 
                    if(opt_ts_offset == -1) return XDP_DROP;
                    // Store rx packet's Tsval (in order to put into Tsecr)
                    ts->tsval = bpf_htonl(TS_START);
            }
            else{
                DEBUG_PRINT("No options TCP packet ingress, Foward\n");
            }
        }
    }
    return XDP_PASS;
}
