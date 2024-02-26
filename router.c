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
            DEBUG_PRINT("Router: TCP packet (with options) ingress  , Foward\n");

                if(tcp->syn && (!tcp->ack)) {

                // SYN with no option (assume not happen)
                // if happen, go bloomfilter way ?
                
                
                // if has tcp option, check has tcptimestamp ?
                // if yes, header shrink to 20 + sizeof(synack_opt_order_1);
                // Then put cookie into Tsval.
                // How to determine cookie ? Halfsiphash for every flow or predefine secret number? 
                
                    DEBUG_PRINT ("Router: Syn packet with option ingress\n");
                    struct tcp_opt_ts* ts;
                    __u32 rx_tsval = 0;
                    int opt_ts_offset = parse_syn_timestamp(&cur,data_end,&ts); 
                    if(opt_ts_offset == -1) return XDP_DROP;
                    // Store rx packet's Tsval (in order to put into Tsecr)
                    rx_tsval = ts->tsval;

                    // Store imformation before shrink
                    // IP
                    __u16 old_ip_csum = ip->check;
                    __u32 old_ip_totlen = ip->tot_len;
                    __u32 orig_src_ip = ip->saddr;
                    __u32 orig_dst_ip = ip->daddr;
                    // TCP
                    __u16 orig_src_port = tcp->source;
                    __u16 orig_dst_port = tcp->dest;
                    __u32 rx_seq = tcp->seq;
                    //__u32 rx_ack = tcp->ack_seq;
                    //__u16 old_tcp_csum = tcp->check;
                    int delta = (int)(sizeof(struct tcphdr) + sizeof(struct common_synack_opt)) - (tcp->doff*4);
                    
                    // Modify lenth information before shrink.
                    __u32 new_ip_totlen = bpf_htons(bpf_ntohs(ip->tot_len) + delta);
                    ip->tot_len = new_ip_totlen;
                    tcp->doff += delta/4 ;
                    
                    // shrink packet
                    int result = bpf_xdp_adjust_tail(ctx, delta);
                    if (result) {
                        DEBUG_PRINT ("Router: Adjust_tail fail!\n");
                        return XDP_DROP;
                    }
                    else{
                        DEBUG_PRINT ("Router: Adjust_tail by %d bytes success!\n",delta);
                    }
                    
                    data_end = (void*)(long)ctx->data_end;
                    data = (void *)(long)ctx->data;
                    cur.pos = data;

                    // Re bounded pointer
                    ether_proto = parse_ethhdr(&cur,data_end,&eth);
                    if(ether_proto == -1) return XDP_DROP; 
                    ip_proto = parse_iphdr(&cur, data_end, &ip);
                    if(ip_proto == -1) return XDP_DROP;
                    tcphdr_len = parse_tcphdr(&cur, data_end, &tcp);
                    if(tcphdr_len == -1) return XDP_DROP;

                    ip->saddr = orig_dst_ip;
                    ip->daddr = orig_src_ip;

                    //## Update ip checksum
                    // bfp_csum_diff 's seed need to add "~~~~~~~~~~~~~~~~~~"
                    //## Since only change ip_totlen new ip_csum
                    // to __bultin_bswap32() depend on header's position
                    ip->check = csum_fold_helper_64(bpf_csum_diff((__u32*)&old_ip_totlen,4
                                                                 ,(__u32*)&new_ip_totlen,4,~old_ip_csum));
                  
                    // Modify tcphdr after shrink packet
                    tcp->seq = get_hash(orig_src_ip,orig_dst_ip,orig_src_port,orig_dst_port);
                    tcp->ack_seq = rx_seq + bpf_htonl(1);
                    tcp->source = orig_dst_port;
                    tcp->dest = orig_src_port;
                    tcp->syn = 1;
                    tcp->ack = 1;
                    
                    struct common_synack_opt* sa_opt = cur.pos;
                    if((sa_opt + 1) > data_end) return XDP_DROP;
                    
                    sa_opt->MSS = 0xb4050402; //1460
                    sa_opt->SackOK = 0x0204;
                    sa_opt->ts.kind = 8;
                    sa_opt->ts.length = 10;
                    sa_opt->ts.tsecr = rx_tsval;
                    sa_opt->ts.tsval = bpf_htonl(TS_START);
                    // Recompute tcp checksum
                    //if((void*)opt_copy + tcp_opt_len > data_end) return XDP_DROP;

                    // sa_opt is the pointer of my new option part.         
                    //__u64 tcp_csum = 0;
                    // Before recompute, need to reset old csum to 0;
                    // 36 is tcp_seg's size
                    // TODO: How to get tcp_seg size maybe 
                    tcp->check = 0;
                    __u64 tcp_csum_tmp = 0;
                    
                    
                    // Don't know how to bound tcp_len;
                    if(((void*)tcp)+ 36 > data_end) return XDP_DROP;
                    ipv4_l4_csum(tcp, 36, &tcp_csum_tmp, ip); // Use fixed 36 bytes
                    tcp->check = tcp_csum_tmp;
                }  
                else if(tcp->syn && tcp->ack){
                    DEBUG_PRINT("Router:  SYNACK packet ingress, Foward\n");
                }   
                else if(tcp->ack && !tcp->syn){
                    DEBUG_PRINT("Router:  ACK packet ingress\n");
                    struct tcp_opt_ts* ts;
                    
                    __u32 cookie = get_hash(ip->saddr, ip->daddr, tcp->source, tcp->dest);
                    int opt_ts_offset = parse_ack_timestamp(&cur,data_end,&ts); 
                    if(opt_ts_offset == -1) return XDP_DROP;
                    if(ts->tsecr == bpf_htonl(TS_START)){
                        DEBUG_PRINT("Router: ACK packet with tsecr == TS_START ingress\n");
                        __u32 rx_ack = tcp->ack_seq;
                        if(rx_ack - bpf_htonl(1) == cookie){
                            DEBUG_PRINT ("Router: ACK packet with TS_START pass ACK cookie check!\n");
                        }
                        else{
                            DEBUG_PRINT ("Router: ACK packet with TS_START fail ACK cookie check!\n");
                            return XDP_DROP;
                        }
                    }
                    else{
                        DEBUG_PRINT("Router: ACK packet with tsecr != TS_START ingress!\n");
                        if(ts->tsecr == cookie){
                            DEBUG_PRINT ("Router: ACK packet pass Timestamp cookie!\n");
                        }
                        else{
                            DEBUG_PRINT ("Router: ACK packet fail Timestamp cookie!\n");
                            return XDP_DROP;
                        }
                    }
                }
                else{
                    DEBUG_PRINT("Router: Other packet ingress, Foward\n");
                    

                }
            
            }
            else{
                DEBUG_PRINT("Router: No options TCP packet ingress, Foward\n");
                

            }
        } 
        if (ip->ttl <= 1) return XDP_PASS;        
        fib_params.family = AF_INET;
        fib_params.tos = ip->tos;
        fib_params.l4_protocol = ip->protocol;
        fib_params.sport = 0;
        fib_params.dport = 0;
        // fib_params.tot_len is little-endian
        fib_params.tot_len = bpf_ntohs(ip->tot_len);
        fib_params.ipv4_src = ip->saddr;
        fib_params.ipv4_dst = ip->daddr;
        goto forward;
    }
    return XDP_PASS;

forward:
    fib_params.ifindex = ctx->ingress_ifindex;
    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    DEBUG_PRINT("Router: Foward to interface_%d\n",rc);
    switch(rc) {
        case BPF_FIB_LKUP_RET_SUCCESS:
            DEBUG_PRINT("Router: Success\n");
            _decr_ttl(ether_proto, ip);
            __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
            return bpf_redirect(fib_params.ifindex, 0);
        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            DEBUG_PRINT("Router: XDP Drop in switchcase\n");
            return XDP_DROP;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            DEBUG_PRINT("Router: XDP Pass in switchcase\n");
            return XDP_PASS;
    }
    return XDP_PASS;
}
