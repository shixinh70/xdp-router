
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
#include <linux/pkt_cls.h>
#include "router.h"
#define MAX_ENTRY 2000


char _license[] SEC("license") = "GPL";

struct eth_mac_t
{
    __u8 buf[6];
}__attribute__((packed));


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
SEC("prog") int xdp_router(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct hdr_cursor cur;
    struct ethhdr* eth;
    struct iphdr* ip;
    struct tcphdr* tcp;

    cur.pos = data;
    int ether_proto ;
    ether_proto = parse_ethhdr(&cur,data_end,&eth);
    if(ether_proto == -1) return TC_ACT_SHOT;
    
    if (bpf_htons(ether_proto) == ETH_P_IP) {

        int ip_proto = parse_iphdr(&cur, data_end, &ip);
        if(ip_proto == -1) return TC_ACT_SHOT;
        if(ip_proto == IPPROTO_TCP){
        

            int tcphdr_len = parse_tcphdr(&cur, data_end, &tcp);
            if(tcphdr_len == -1) return TC_ACT_SHOT;
            if(tcphdr_len >= 32){ // Timestamp need 12 byte (Nop Nop timestamp)
            struct tcp_opt_ts* ts;
            DEBUG_PRINT("TC:TCP packet (with options) ingress\n");

            // This parse timestamp may can be optimize
            // Switch agent have parse the timestamp so can put the ts type
            // in some un-used header field.
            // TODO: Finish parse_synack.

            int opt_ts_offset = parse_synack_timestamp(&cur,data_end,&ts);
            if(opt_ts_offset == -1) return TC_ACT_SHOT;
            
            // Find pin_map (key = 4 turple); Q: key's order?
            struct map_key_t key = {
                    .src_ip = ip->daddr,
                    .dst_ip = ip->saddr,
                    .src_port = tcp->dest,
                    .dst_port = tcp->source
                };
            struct map_val_t val;
            struct map_val_t* val_p = bpf_map_lookup_elem(&conntrack_map,&key);
            if(val_p) {
                DEBUG_PRINT ("TC:Connection exist in map!\n");
            }
            else {
                DEBUG_PRINT ("TC:Connection not exist in map!\n");
                
            }
            // Read val from pinned map;
            if( bpf_probe_read_kernel(&val,sizeof(val),val_p) != 0){
                DEBUG_PRINT ("TC:Read map_val fail!\n");
                return TC_ACT_SHOT;
            }
            

                // if SYN-ACK packet (from server)
                // Swap ip address, port, timestamp, mac. and conver it to ack.
                if(tcp->ack && tcp->syn){
                    DEBUG_PRINT ("TC:SYNACK packet ingress! csum = %x\n",bpf_ntohs(tcp->check));

                    // Modify delta (need to check the byte order problem)
                    val.delta -= (tcp->ack_seq + (bpf_htonl(1)));
                    DEBUG_PRINT("TC:Update delta = %u\n", bpf_htonl(val.delta));
                    //BPF_EXIST will update an existing element (may have bug)
                    bpf_map_update_elem(&conntrack_map,&key,&val,BPF_EXIST);

                    // Swap ip
                    ip->saddr ^= ip->daddr;
                    ip->daddr ^= ip->saddr;
                    ip->saddr ^= ip->daddr;

                    // Swap port and convert to ack packet
                    __u64 tcp_csum = tcp->check;
                    __u32* ptr ; 
                    ptr = ((void*)tcp) + 12;
                    if((void*)ptr + 4 > data_end) return XDP_DROP;
                       
                    __u32 tcp_old_flag = *ptr;
                    tcp->syn = 0;tcp->ack = 1;
                    __u32 tcp_new_flag = *ptr;
                    

                    tcp->source ^= tcp->dest;
                    tcp->dest ^= tcp->source;
                    tcp->source ^= tcp->dest;

                    tcp->seq ^= tcp->ack_seq;
                    tcp->ack_seq ^= tcp->seq;
                    tcp->seq ^= tcp->ack_seq;
                    tcp->seq += bpf_htonl(1);

                    tcp_csum = bpf_csum_diff(&tcp_old_flag, 4, &tcp_new_flag, 4, ~tcp_csum);
                    tcp_csum -= bpf_htonl(1);
                    tcp->check = csum_fold_helper_64(tcp_csum);

                    // Swap tsval and tsecr. Do we need to change the ts order to NOP NOP TS ?   
                    ts->tsval ^= ts->tsecr;
                    ts->tsecr ^= ts->tsval;
                    ts->tsval ^= ts->tsecr;

                    // Swap mac.
                    struct eth_mac_t mac_tmp;
                    __builtin_memcpy(&mac_tmp, eth->h_source, 6);
                    __builtin_memcpy(eth->h_source, eth->h_dest, 6);
                    __builtin_memcpy(eth->h_dest, &mac_tmp, 6);
                    
                    //bpf_skb_store_bytes(skb, sizeof(*eth) + )
                }
                
            
            }
            else{
                DEBUG_PRINT("TC:No options TCP packet ingress, Foward\n");

            }
        } 
    }
    return TC_ACT_OK;
}
