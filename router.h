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
#include <stddef.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>

#ifndef ROUTER_H
#define ROUTER_H
#define DEBUG 1
#define DEBUG_PRINT(fmt, ...) if (DEBUG) bpf_printk(fmt, ##__VA_ARGS__)
#define TS_START 1
#define MAX_TRUNK_VLANS 8
#define MAX_IFACES 16
#define MAX_TCP_OPTION 10
#define SIPROUND \
	do { \
	v0 += v1; v2 += v3; v1 = rol(v1, 5); v3 = rol(v3,8); \
	v1 ^= v0; v3 ^= v2; v0 = rol(v0, 16); \
	v2 += v1; v0 += v3; v1 = rol(v1, 13); v3 = rol(v3, 7); \
	v1 ^= v2; v3 ^= v0; v2 = rol(v2, 16); \
	} while (0)
    
const int key0 = 0x33323130;
const int key1 = 0x42413938;
const int c0 = 0x70736575;
const int c1 = 0x6e646f6d;
const int c2 = 0x6e657261;
const int c3 = 0x79746573;

//SYN
//MSS, SackOk, Timestamp
const __u64 syn_1_mask = 0x0008000400000002;
// MSS, NOP, WScale, NOP, NOP, Timestamp
// 0x 02000000 01 070000 01 01 08
const __u64 syn_2_mask_1 = 0x0000070100000002;
const __u32 syn_2_mask_2 = 0x08010100;
// MSS, NOP, WScale, SAckOK, Timestamp
const __u64 syn_3_mask_1 = 0x0000070100000002;
const __u32 syn_3_mask_2 = 0x08000400;

//ACK
//NOP NOP Timstamp
const __u64 ack_1_mask = 0x000000000080101;

//SYNACK
//MSS SackOk, Timestamp
const __u64 synack_1_mask = ack_1_mask;
//MSS NOP Wscale SackOk Timestamp
const __u64 synack_2_mask_1 = syn_2_mask_1;
const __u32 synack_2_mask_2 = syn_3_mask_2;
//MSS NOP NOP Timestamp 
const __u64 synack_3_mask = 0x0008010100000004;
//MSS NOP WScale NOP NOP Timestamp
const __u64 synack_4_mask_1 = syn_2_mask_1;
const __u32 synack_4_mask_2 = syn_2_mask_2;


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


static __always_inline void _decr_ttl(__u16 proto, void *h) {
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



static inline __u32 rol(__u32 word, __u32 shift){
	return (word<<shift) | (word >> (32 - shift));
}



static __always_inline __u32 get_hash(__u32 src, __u32 dst, __u16 src_port, __u16 dst_port ){
	
	//initialization 
	int v0 = c0 ^ key0;
	int v1 = c1 ^ key1;
	int v2 = c2 ^ key0;
	int v3 = c3 ^ key1; 
	
	//first message 
	v3 = v3 ^ bpf_ntohl(src);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ bpf_ntohl(src); 

	//second message 
	v3 = v3 ^ bpf_ntohl(dst);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ bpf_ntohl(dst); 

	//third message
	__u32 ports = (__u32) dst_port << 16 | (__u32) src_port;  
	v3 = v3 ^ bpf_ntohl(ports);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ bpf_ntohl(ports); 
	
	//finalization
	v2 = v2 ^ 0xFF; 
	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;

	__u32 hash = (v0^v1)^(v2^v3);
	hash %= bpf_htonl(0x80000000);
    return hash; 	
}
static __always_inline __u32 get_hash_2(__u32 src, __u32 dst, __u16 src_port, __u16 dst_port ){
	
	//initialization 
	int v0 = c0 ^ key0;
	int v1 = c1 ^ key1;
	int v2 = c2 ^ key0;
	int v3 = c3 ^ key1; 
	
	//first message 
	v3 = v3 ^ bpf_ntohl(src);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ bpf_ntohl(src); 

	//second message 
	v3 = v3 ^ bpf_ntohl(dst);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ bpf_ntohl(dst); 

	//third message
	__u32 ports = (__u32) dst_port << 16 | (__u32) src_port;  
	v3 = v3 ^ bpf_ntohl(ports);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ bpf_ntohl(ports); 
	
	//finalization
	v2 = v2 ^ 0xFF; 
	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;

	__u32 hash = (v0^v1)^(v2^v3);
        return hash; 	
}
struct hdr_cursor {
	void *pos;
};


static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr){

	struct ethhdr *ethh = nh->pos;
	int hdrsize;
	hdrsize = sizeof(struct ethhdr);

	if(ethh + 1 > data_end){
		DEBUG_PRINT("Drop at router.h 122\n");
		return -1;

	}
	
	if(nh->pos + hdrsize > data_end){
		DEBUG_PRINT("Drop at router.h 128\n");
		return -1;

	}

	nh->pos += hdrsize;
	*ethhdr = ethh;

	return ethh->h_proto;
}


static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end){
		return -1;
		DEBUG_PRINT("Drop at router.h 147\n");
	}
		

	hdrsize = iph->ihl * 4;
	/* Sanity check packet field is valid */
	if(hdrsize < sizeof(*iph)){
		DEBUG_PRINT("Drop at router.h 147\n");
		return -1;
	}
	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end){
		return -1;
		DEBUG_PRINT("Drop at router.h 152\n");
	}
		

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

/*
 * parse_tcphdr: parse and return the length of the tcp header
 */

static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
										void *data_end,
										struct tcphdr **tcphdr)
{
	int len;
	struct tcphdr *h = nh->pos;

	if (h + 1 > data_end){
        DEBUG_PRINT("Drop at router.h 194\n");
		return -1;
	}
	len = h->doff * 4;
	/* Sanity check packet field is valid */
	if(len < (int)sizeof(*h)){
        DEBUG_PRINT("Drop at router.h 200\n");
		return -1;
	}
	/* Variable-length TCP header, need to use byte-based arithmetic */
	if (nh->pos + len > data_end){
        DEBUG_PRINT("Drop at router.h 205\n");
		return -1;
	}
	nh->pos = h + 1 ;
	*tcphdr = h;

	return len;
}

static inline __u32 parse_timestamp(struct hdr_cursor *nh,
									struct tcphdr* tcp, 
									void *data_end,
									struct tcp_opt_ts **tshdr) {
	struct tcp_opt_ts* ts;
    int opt_ts_offset = -1;
	int found = 0;
    //void* l4hdr = (data + sizeof(strct ethhdr))
    __u64* tcp_opt_64 = nh->pos;
	DEBUG_PRINT("Parsing timestamp offset...\n");
	if(tcp_opt_64 + 1 > data_end){
		DEBUG_PRINT("Drop at parse_syn_timestamp\n");

		return -1;
	}
	
	if(tcp->syn && !tcp->ack){
		// Mask: MSS(4B), SackOK(2B), Timestamp(1B)
		if((syn_1_mask & *tcp_opt_64) == syn_1_mask){
			DEBUG_PRINT("Match Mss, SackOK, Timestamp\n");
			found = 1;
			opt_ts_offset = 6;
			// ts = (struct tcp_opt_ts*)(l4hdr + 20 + 6);
			// if((void*)ts + sizeof(struct tcp_opt_ts) > data_end) return -1;
			// rx_tsval = ts->tsval;
		}
		// Mask: Nop Nop TS (For testing hping3's Timestamp option, not common in real world)
		// else if((ack_1_mask & *tcp_opt_64) == ack_1_mask){
		//     DEBUG_PRINT("Match NOP, NOP, Timestamp\n");
		//     opt_ts_offset = 2;
		//     // ts = (struct tcp_opt_ts*)(l4hdr + 20 + 6);
		//     // if((void*)ts + sizeof(struct tcp_opt_ts) > data_end) return -1;
		//     // rx_tsval = ts->tsval;
		// }

		else{
			//nh->pos += 8;
			__u32* tcp_opt_32 = nh->pos + 8;
			if(tcp_opt_32 + 1 > data_end){
				DEBUG_PRINT("Drop at parse_syn_timestamp\n");
				return -1;
			}
			if((syn_2_mask_1 & *tcp_opt_64) == syn_2_mask_1){
				if((syn_2_mask_2 & *tcp_opt_32) == syn_2_mask_2){
					DEBUG_PRINT("Match MSS, NOP, WScale, NOP, NOP, Timestamp\n");
					opt_ts_offset = 10;
					found = 1;

					// ts = (struct tcp_opt_ts*)(l4hdr + 20 + 10);
				}  
			}
			else if((syn_3_mask_1 & *tcp_opt_64) == syn_3_mask_1){
				if((syn_3_mask_2 & *tcp_opt_32) == syn_3_mask_2){
					DEBUG_PRINT("Match // MSS, NOP, WScale, SAckOK, Timestamp\n");
					opt_ts_offset = 10;
					found = 1;
					// ts = (struct tcp_opt_ts*)(l4hdr + 20 + 10);
				}  
			}
		}
		
	}
	if(tcp->ack && !tcp->syn){
		if((ack_1_mask & *tcp_opt_64) == ack_1_mask){
			DEBUG_PRINT("Match NOP, NOP, Timestamp\n");
			opt_ts_offset = 2;
			found = 1;

			// ts = (struct tcp_opt_ts*)(l4hdr + 20 + 6);
			// if((void*)ts + sizeof(struct tcp_opt_ts) > data_end) return -1;
			// rx_tsval = ts->tsval;
		}
		// else{
		// 	DEBUG_PRINT("Slow path match timestamp\n");
		// }
	}
	if(tcp->syn && tcp->ack){
		if((synack_1_mask & *tcp_opt_64) == synack_1_mask){
			DEBUG_PRINT("Match SackOk, Timestamp\n");
			found = 1;
			opt_ts_offset = 2;
			// ts = (struct tcp_opt_ts*)(l4hdr + 20 + 6);
			// if((void*)ts + sizeof(struct tcp_opt_ts) > data_end) return -1;
			// rx_tsval = ts->tsval;
    	}
		else{
			//nh->pos += 8;
			__u32* tcp_opt_32 = nh->pos + 8;
			if(tcp_opt_32 + 1 > data_end){
				DEBUG_PRINT("Drop at parse_syn_timestamp\n");
				return -1;
			}
			if((synack_2_mask_1 & *tcp_opt_64) == synack_2_mask_1){
				if((synack_2_mask_2 & *tcp_opt_32) == synack_2_mask_2){
					DEBUG_PRINT("Match MSS NOP WScale SackOK Timestamp\n");
					opt_ts_offset = 10;
					found = 1;

					// ts = (struct tcp_opt_ts*)(l4hdr + 20 + 10);
				}  
			}
			else if((synack_3_mask & *tcp_opt_64) == synack_3_mask){
				if((syn_3_mask_2 & *tcp_opt_32) == syn_3_mask_2){
					DEBUG_PRINT("Match MSS NOP NOP Timestamp\n");
					opt_ts_offset = 6;
					found = 1;
					// ts = (struct tcp_opt_ts*)(l4hdr + 20 + 10);
				}  
			}
			else if((synack_4_mask_1 & *tcp_opt_64) == synack_4_mask_1){
				if((synack_4_mask_2 & *tcp_opt_32) == synack_4_mask_2){
					DEBUG_PRINT("Match MSS NOP WScale NOP NOP Timestamp\n");
					opt_ts_offset = 10;
					found = 1;
					// ts = (struct tcp_opt_ts*)(l4hdr + 20 + 10);
				}  
			}
		}
	}

	if(!found){
		DEBUG_PRINT("Slow path match timestamp\n");
		__u8* opt = (void*)(tcp + 1);
		void* opt_end = (void*) tcp + (tcp->doff * 4);
		volatile __u8 opt_len;
		
		#pragma unroll
		for(int i =0;i<MAX_TCP_OPTION;i++){
			if(opt + 1 > opt_end || opt + 1 > data_end){
				DEBUG_PRINT("No timestamp and reach opt_end or data_end\n");
				return -1;
			}
			if(*opt == 0){
				DEBUG_PRINT("No timestamp and reach end of list\n");
				return -1;
			}
			if(*opt == 1){
				// Find NOP(1B) continued;
				opt++;
				continue;
			}
			if(opt + 2 > opt_end || opt + 2 > data_end){
				return -1;
			}
			opt_len = *(opt + 1);

			// option 2 ---> MSS(4B)
			if(*opt != 8){
				
				opt += opt_len;
			}
			else{
				ts = opt;
				if( ts+1 > data_end){
					return -1;
				}
				opt_ts_offset = (void*)opt - (void*)nh->pos;
				nh->pos = ts + 1;
				*tshdr = ts;
				DEBUG_PRINT("opt_ts_offset = %d\n", opt_ts_offset);
				return opt_ts_offset;					
			}
		}
	}

	if(!found){
		return -1;
	}

	nh->pos += opt_ts_offset;
	if(nh->pos + opt_ts_offset > data_end) return -1;
	ts = nh->pos;
	if(ts + 1 > data_end){
		return -1;
	} 
	nh->pos = ts + 1;
	*tshdr = ts;
	return opt_ts_offset;

}





static inline __u32 parse_ack_timestamp(struct hdr_cursor *nh,
									void *data_end,
									struct tcp_opt_ts **tshdr) {
	struct tcp_opt_ts* ts;
    int opt_ts_offset = -1;
    //void* l4hdr = (data + sizeof(strct ethhdr))
    __u64* tcp_opt_64 = nh->pos;
	if(tcp_opt_64 + 1 > data_end){
        DEBUG_PRINT("Drop at parse_ack_timestamp\n");
		return -1;
	}

    // Mask: NOP NOP TS
    if((ack_1_mask & *tcp_opt_64) == ack_1_mask){
        DEBUG_PRINT("Match NOP, NOP, Timestamp\n");
        opt_ts_offset = 2;
        // ts = (struct tcp_opt_ts*)(l4hdr + 20 + 6);
        // if((void*)ts + sizeof(struct tcp_opt_ts) > data_end) return -1;
        // rx_tsval = ts->tsval;
    }
	else{
		DEBUG_PRINT("Slow path match timestamp\n");
	}

	nh->pos += opt_ts_offset;
	if(nh->pos + opt_ts_offset > data_end) return -1;
	ts = nh->pos;
	if(ts + 1 > data_end){
        DEBUG_PRINT("Drop at parse_ack_timestamp\n");
		return -1;
	} 
	nh->pos = ts + 1;
	*tshdr = ts;
    return opt_ts_offset;
}

static inline __u32 parse_synack_timestamp(struct hdr_cursor *nh,
									void *data_end,
									struct tcp_opt_ts **tshdr) {
	struct tcp_opt_ts* ts;
    int opt_ts_offset = -1;
    //void* l4hdr = (data + sizeof(strct ethhdr))
    __u64* tcp_opt_64 = nh->pos;
	if(tcp_opt_64 + 1 > data_end){
        DEBUG_PRINT("Drop at parse_ack_timestamp\n");
		return -1;
	}

    // Mask: MSS(4B), SackOK(2B), Timestamp(1B)
    if((ack_1_mask & *tcp_opt_64) == ack_1_mask){
        DEBUG_PRINT("Match NOP, NOP, Timestamp\n");
        opt_ts_offset = 2;
        // ts = (struct tcp_opt_ts*)(l4hdr + 20 + 6);
        // if((void*)ts + sizeof(struct tcp_opt_ts) > data_end) return -1;
        // rx_tsval = ts->tsval;
    }
	else{
		DEBUG_PRINT("TC:Slow path match timestamp\n");
		opt_ts_offset = 6;
	}

	nh->pos += opt_ts_offset;
	if(nh->pos + opt_ts_offset > data_end) return -1;
	ts = nh->pos;
	if(ts + 1 > data_end){
        DEBUG_PRINT("Drop at parse_ack_timestamp\n");
		return -1;
	} 
	nh->pos = ts + 1;
	*tshdr = ts;
    return opt_ts_offset;
}
#endif // ROUTER_H
