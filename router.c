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


#define DEBUG 1
#define DEBUG_PRINT(fmt, ...) if (DEBUG) bpf_printk(fmt, ##__VA_ARGS__)

#include "router.h"

char _license[] SEC("license") = "GPL";

struct tcp_opt_ts {
    __u8 kind;      
    __u8 length;    
    __u32 tsval;    
    __u32 tsecr;    
}__attribute__((packed));

struct common_synack_opt {
    __u32 MSS;      
    __u16 SackOK;    
    struct tcp_opt_ts ts;        
}__attribute__((packed));


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

static __always_inline void ipv4_l4_csum(void* data_start, __u64 data_size, __u64* csum, struct iphdr* iph) {

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
    struct ethhdr *eth = data;

    long rc;

    // invalid pkt: ethhdr overflow
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_DROP;
    }

    // ptr to l3 protocol headers (or inner l2, if vlan)
    void *l3hdr = data + sizeof(struct ethhdr);

    // ethertype
    __u16 ether_proto = bpf_ntohs(eth->h_proto);

    struct bpf_fib_lookup fib_params = {};

    if (ether_proto == ETH_P_IP) {

        //Check l3 header bound
        if (l3hdr + sizeof(struct iphdr) > data_end) return XDP_DROP;
        struct iphdr *ip = l3hdr;
        if(ip->protocol == IPPROTO_TCP){

            void *l4hdr = ip + 1;

            //Check l4 header bound
            if(l4hdr + sizeof(struct tcphdr) > data_end) return XDP_DROP;
            struct tcphdr* tcp = (struct tcphdr*)l4hdr;
            __u8 tcphdr_len = (tcp->doff * 4);

            // if is SYN packet
            if(tcp->syn) {

                // SYN with no option (assume not happen)
                // if happen, go bloomfilter way ?
                if (tcphdr_len == 20){
                    // grow 12 byte at the packet's tail;
                    int delta = 12;
                    int result = bpf_xdp_adjust_tail(ctx, delta);
                    if (result) {
                        DEBUG_PRINT ("adjust_tail fail!\n");
                        return XDP_DROP;
                    }
                    // redo bound check

                    data_end = (void*)(long)ctx->data_end;
                    data = (void *)(long)ctx->data;
                    eth = data;

                    // eth 
                    if (data + sizeof(struct ethhdr) > data_end) {
                        DEBUG_PRINT("eth check fail\n");
                        return XDP_DROP;
                    }

                    // l3
                    l3hdr = data + sizeof(struct ethhdr);
                    if (l3hdr + sizeof(struct iphdr) > data_end){
                        DEBUG_PRINT("l3 check fail\n");
                        return XDP_DROP;
                    }
                    ip = l3hdr;
                    
                    // Store old checksum for later update checksum
                    __u16 old_ip_csum = ip->check;

                    // Clear old checksum
                    ip->check = 0;

                    // Copy old ip datagram
                    struct iphdr old_ip_hdr = *ip;

                    // Update iphdr's total length, as tcp packet has grow delta bytes
                    ip->tot_len += bpf_htons(delta);

                    // Update iphdr's checksum
                    ip->check = ip_checksum_diff(~old_ip_csum, ip, &old_ip_hdr);

                    //l4
                    l4hdr = ip + 1;
                    if(l4hdr + sizeof(struct tcphdr) > data_end){
                        DEBUG_PRINT("l4 check fail\n");
                        return XDP_DROP;
                    } 
                    tcp = (struct tcphdr*)l4hdr;
                    
                    // The option will be NOP(1 Byte) NOP(1 Byte) TS(10 Bytes)
                    // ts will at the position of tcphdr + old_headerlen (20 Bytes) + 2 Bytes (Two NOPs) 
                    struct tcp_opt_ts* ts = (struct tcp_opt_ts*)((char*)tcp + tcphdr_len + 2);
                    if ((void*)ts + sizeof(struct tcp_opt_ts) > data_end){
                        DEBUG_PRINT("ts check fail\n");
                        return XDP_DROP;

                    }
                    // Set the 2 Byte's Space to NOP (kind = 1)
                    __builtin_memset((void*)ts-2, 1, 2);

                    // Fill in Ts option's val.
                    ts->kind = 8;
                    ts->length = 10;
                    ts->tsecr = 0;
                    ts->tsval = bpf_htonl(67890);

                    // Update the tcphdr_len
                    tcp->doff += (delta/4);
                    
                }
                
                // if has tcp option, check has tcptimestamp ?
                // if yes, header shrink to 20 + sizeof(synack_opt_order_1);
                // Then put cookie into Tsval.
                // How to determine cookie ? Halfsiphash for every flow or predefine secret number? 
                else{
                    DEBUG_PRINT ("SYN packet with options in\n");
                    // MSS, SackOk, Timestamp
                    // Little endian
                    struct tcp_opt_ts* ts;
                    __u64 type1_mask = 0x0008000400000002;
                    // MSS, NOP, WScale, NOP, NOP, Timestamp
                    // 0x 02000000 01 070000 01 01 08
                    __u64 type2_mask_1 = 0x0000070100000002;
                    __u32 type2_mask_2 = 0x08010100;
                    __u32 rx_tsval = 0;
                    __u32 opt_ts_offset = 0;
                    __u64* tcp_opt_64 = (__u64*)(l4hdr + 20);
                    if((void*)tcp_opt_64 + sizeof(__u64) > data_end) return XDP_DROP;
                    __u32* tcp_opt_32 = (__u32*)(l4hdr + 28);
                    if((void*)tcp_opt_32 + sizeof(__u32) > data_end) return XDP_DROP;
                    
                    // Mask: MSS(4B), SackOK(2B), Timestamp(1B)
                    if((type1_mask & *tcp_opt_64) == type1_mask){
                        DEBUG_PRINT("Match Mss, SackOK, Timestamp\n");
                        opt_ts_offset = 26;
                        // ts = (struct tcp_opt_ts*)(l4hdr + 20 + 6);
                        // if((void*)ts + sizeof(struct tcp_opt_ts) > data_end) return XDP_DROP;
                        // rx_tsval = ts->tsval;
                    }
                    // Mask: MSS(4B), NOP(1B), WScale(3B), NOP(1B), NOP(1B), Timestamp(1B)
                    else if((type2_mask_1 & *tcp_opt_64) == type2_mask_1){
                        if((type2_mask_2 & *tcp_opt_32) == type2_mask_2){
                            DEBUG_PRINT("Match MSS, NOP, WScale, NOP, NOP, Timestamp\n");
                            opt_ts_offset = 30;
                            // ts = (struct tcp_opt_ts*)(l4hdr + 20 + 10);
                        }  
                    }
                    // TODO:other common order and loop find Ts.
                    // Have option but no timestamp
                    else{ 
                        DEBUG_PRINT("No Timestamp in options\n");
                    }

                    // Store rx packet's Tsval (in order to put into Tsecr)
                    ts = (struct tcp_opt_ts*)(l4hdr + opt_ts_offset);
                    if((void*)ts + sizeof(struct tcp_opt_ts) > data_end) return XDP_DROP;
                    rx_tsval = ts->tsval;

                    // Shrink rx packet's header len to 20 + sizeof(common_synack_opt)
                    // If change packet len, need to modify IP tot_len, and recompute IP checksum.
                    // All the bound check will cancel after bpf_xdp_adjust_tail()

                    // Store imformation before shrink

                    // IP
                    __u16 old_ip_csum = ip->check;
                    ip->check = 0;
                    struct iphdr old_ip_hdr = *ip;
                
                    // shrink packet
                    int delta = (int)(20 + sizeof(struct common_synack_opt)) - (tcp->doff*4);
                    int result = bpf_xdp_adjust_tail(ctx, delta);
                    if (result) {
                        DEBUG_PRINT ("adjust_tail fail!\n");
                        return XDP_DROP;
                    }
                    else{
                        DEBUG_PRINT ("adjust_tail by %d bytes success!\n",delta);
                    }
                    
                    data_end = (void*)(long)ctx->data_end;
                    data = (void *)(long)ctx->data;
                    eth = data;
                    // eth 
                    if (data + sizeof(struct ethhdr) > data_end) {
                        DEBUG_PRINT("eth check fail\n");
                        return XDP_DROP;
                    }
                    // l3
                    l3hdr = data + sizeof(struct ethhdr);
                    if (l3hdr + sizeof(struct iphdr) > data_end){
                        DEBUG_PRINT("l3 check fail\n");
                        return XDP_DROP;
                    }
                    ip = l3hdr;

                    __u32 orig_src_ip = ip->saddr;
                    __u32 orig_dst_ip = ip->daddr;
                    ip->saddr = orig_dst_ip;
                    ip->daddr = orig_src_ip;
                    DEBUG_PRINT("origin ip->tot_len = %d\n",bpf_ntohs(ip->tot_len));
                    ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + delta);

                    // Update ip checksum
                    ip->check = ip_checksum_diff(~old_ip_csum, ip, &old_ip_hdr);

                    // l4
                    l4hdr = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                    if (l4hdr + sizeof(struct tcphdr) > data_end){
                        DEBUG_PRINT("l4 check fail\n");
                        return XDP_DROP;
                    }
                    tcp = l4hdr;

                    // Modify tcphdr after shrink packet
                    __u16 orig_src_port = tcp->source;
                    __u16 orig_dst_port = tcp->dest;
                    __u32 rx_seq = tcp->seq;
                    __u32 rx_ack = tcp->ack_seq;

                    tcp->seq = bpf_get_prandom_u32();
                    tcp->ack_seq = rx_seq + bpf_htonl(1);
                    tcp->source = orig_dst_port;
                    tcp->dest = orig_src_port;
                    tcp->syn = 1;
                    tcp->ack = 1;
                    tcp->doff -= 1;
                    
                    DEBUG_PRINT("tcp->doff = %d\n",tcp->doff);
                    struct common_synack_opt* sa_opt = (struct common_synack_opt*)(tcp + 1);
                    if((void*)(sa_opt + 1) > data_end) return XDP_DROP;
                    
                    sa_opt->MSS = 0xb4050402; //1460
                    sa_opt->SackOK = 0x0204;
                    sa_opt->ts.kind = 8;
                    sa_opt->ts.length = 10;
                    sa_opt->ts.tsecr = rx_tsval;
                    sa_opt->ts.tsval = bpf_ntohl(66666);

                    // Recompute tcp checksum
                    __u64 tcp_csum = 0;
                    DEBUG_PRINT("tcp->doff *4 = %d\n",tcp->doff * 4);

                    // Before recompute, need to reset old csum to 0;
                    // 36 is tcp_seg's size
                    // TODO: How to get tcp_seg size
                    tcp->check = 0;

                    // Don't know how to bound tcp_len;
                    __u64 tcp_len = data_end - (void*)tcp; 
                    DEBUG_PRINT("tcp_len = %d\n",tcp_len);
                    ipv4_l4_csum(tcp, 36, &tcp_csum, ip); // Use fixed 36 bytes
                    tcp->check = tcp_csum;
                   
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
            _decr_ttl(ether_proto, l3hdr);
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