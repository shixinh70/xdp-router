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
static inline void _decr_ttl(__u16 proto, void *h) {
    if (proto == ETH_P_IP) {
        struct iphdr *ip = h;
        __u32 c = ip->check;
        c += bpf_htons(0x0100);
        ip->check = (__u16)(c + (c >= 0xffff));
        --ip->ttl;
    } else if (proto == ETH_P_IPV6) --((struct ipv6hdr*) h)->hop_limit;
}

static __always_inline __u16 csum_fold_helper_64(__u64 csum) {

    int i;
    #pragma unroll
    for (i = 0; i < 4; i++) {
    if (csum >> 16)
        csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static __always_inline void ipv4_l4_csum(void* data_start, const __u64 data_size, __u64* csum, struct iphdr* iph) {
    __u32 tmp = 0;
    *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
    *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
    tmp = __builtin_bswap32((__u32)(iph->protocol));
    *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
    tmp = __builtin_bswap32((__u32)(data_size));
    *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
    *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
    *csum = csum_fold_helper_64(*csum);
}

static __always_inline __u16 ip_checksum_diff(
		__u16 seed,
		struct iphdr *iphdr_new,
		struct iphdr *iphdr_old)
{
	__u32 csum, size = 20;

	csum = bpf_csum_diff((__be32 *)iphdr_old, size, (__be32 *)iphdr_new, size, seed);
	return csum_fold_helper(csum);
}

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
            // if is SYN packet
            if(tcp->syn) {

                // SYN with no option (assume not happen)
                // if happen, go bloomfilter way ?
                if (tcphdr_len == 20){
                    DEBUG_PRINT ("Syn packet without option ingress\n");
                }
                
                // if has tcp option, check has tcptimestamp ?
                // if yes, header shrink to 20 + sizeof(synack_opt_order_1);
                // Then put cookie into Tsval.
                // How to determine cookie ? Halfsiphash for every flow or predefine secret number? 
                else{
                    DEBUG_PRINT ("Syn packet with option ingress\n");
                    struct tcp_opt_ts* ts;
                    __u32 rx_tsval = 0;
                    int opt_ts_offset = parse_timestamp(&cur,data_end,&ts);
                    DEBUG_PRINT("After parse_timestamp\n"); 
                    if(opt_ts_offset == -1) return XDP_DROP;
                    DEBUG_PRINT("115\n"); 

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
                        DEBUG_PRINT ("Adjust_tail fail!\n");
                        return XDP_DROP;
                    }
                    else{
                        DEBUG_PRINT ("Adjust_tail by %d bytes success!\n",delta);
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
                    DEBUG_PRINT("origin ip->tot_len = %d\n",bpf_ntohs(ip->tot_len));

                    //## Update ip checksum
                    // bfp_csum_diff 's seed need to add "~~~~~~~~~~~~~~~~~~"
                    //## Since only change ip_totlen new ip_csum
                    // to __bultin_bswap32() depend on header's position
                    ip->check = csum_fold_helper_64(bpf_csum_diff((__u32*)&old_ip_totlen,sizeof(__u32)
                                                                 ,(__u32*)&new_ip_totlen,sizeof(__u32),~old_ip_csum));
                  
                    // Modify tcphdr after shrink packet
                    tcp->seq = get_hash(orig_src_ip,orig_dst_ip,orig_src_port,orig_dst_port);
                    tcp->ack_seq = rx_seq + bpf_htonl(1);
                    tcp->source = orig_dst_port;
                    tcp->dest = orig_src_port;
                    tcp->syn = 1;
                    tcp->ack = 1;
                    
                    DEBUG_PRINT("tcp->doff = %d\n",tcp->doff);
                    struct common_synack_opt* sa_opt = cur.pos;
                    if((sa_opt + 1) > data_end) return XDP_DROP;
                    
                    sa_opt->MSS = 0xb4050402; //1460
                    sa_opt->SackOK = 0x0204;
                    sa_opt->ts.kind = 8;
                    sa_opt->ts.length = 10;
                    sa_opt->ts.tsecr = rx_tsval;
                    sa_opt->ts.tsval = bpf_ntohl(TS_START);
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
        DEBUG_PRINT("ip->tot_len = %d\n",bpf_ntohs(ip->tot_len));
        fib_params.ipv4_src = ip->saddr;
        fib_params.ipv4_dst = ip->daddr;
        goto forward;
    }

    return XDP_PASS;

forward:
    DEBUG_PRINT("Into Forward\n");
    fib_params.ifindex = ctx->ingress_ifindex;
    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    DEBUG_PRINT("rc = %d\n",rc);
    switch(rc) {
        case BPF_FIB_LKUP_RET_SUCCESS:
            DEBUG_PRINT("Success\n");
            _decr_ttl(ether_proto, ip);
            __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
            DEBUG_PRINT ("%d\n",fib_params.ifindex);
            return bpf_redirect(fib_params.ifindex, 0);
        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            DEBUG_PRINT("Drop\n");
            return XDP_DROP;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            DEBUG_PRINT("BPF_FIB_LKUP_RET_FRAG_NEEDED\n");
            return XDP_PASS;
    }
    return XDP_PASS;
}