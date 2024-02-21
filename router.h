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
#define TS_START 90909090
#define MAX_TRUNK_VLANS 8
#define MAX_IFACES 16
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


//MSS, SackOk, Timestamp
const __u64 syn_1_mask = 0x0008000400000002;
// MSS, NOP, WScale, NOP, NOP, Timestamp
// 0x 02000000 01 070000 01 01 08
const __u64 syn_2_mask_1 = 0x0000070100000002;
const __u32 syn_2_mask_2 = 0x08010100;
// MSS, NOP, WScale, SAckOK, Timestamp
const __u64 syn_3_mask_1 = 0x0000070100000002;
const __u32 syn_3_mask_2 = 0x08000400;

static inline __u32 rol(__u32 word, __u32 shift){
	return (word<<shift) | (word >> (32 - shift));
}



static __u32 get_hash(__u32 src, __u32 dst, __u16 src_port, __u16 dst_port ){
	
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
									void *data_end,
									struct tcp_opt_ts **tshdr) {
	struct tcp_opt_ts* ts;
    int opt_ts_offset = -1;
    //void* l4hdr = (data + sizeof(strct ethhdr))
    __u64* tcp_opt_64 = nh->pos;
	if(tcp_opt_64 + 1 > data_end){
        DEBUG_PRINT("Drop at router.h 222\n");

		return -1;
	}

    // Mask: MSS(4B), SackOK(2B), Timestamp(1B)
    if((syn_1_mask & *tcp_opt_64) == syn_1_mask){
        DEBUG_PRINT("Match Mss, SackOK, Timestamp\n");
        opt_ts_offset = 6;
        // ts = (struct tcp_opt_ts*)(l4hdr + 20 + 6);
        // if((void*)ts + sizeof(struct tcp_opt_ts) > data_end) return -1;
        // rx_tsval = ts->tsval;
    }

	else{
		nh->pos += 8;
		__u32* tcp_opt_32 = nh->pos;
		if(tcp_opt_32 + 1 > data_end){
        	DEBUG_PRINT("Drop at router.h 240\n");
			return -1;
		}
		if((syn_2_mask_1 & *tcp_opt_64) == syn_2_mask_1){
			if((syn_2_mask_2 & *tcp_opt_32) == syn_2_mask_2){
				DEBUG_PRINT("Match MSS, NOP, WScale, NOP, NOP, Timestamp\n");
				opt_ts_offset = 2;
				// ts = (struct tcp_opt_ts*)(l4hdr + 20 + 10);
			}  
   		}
		else if((syn_3_mask_1 & *tcp_opt_64) == syn_3_mask_1){
			if((syn_3_mask_2 & *tcp_opt_32) == syn_3_mask_2){
				DEBUG_PRINT("Match // MSS, NOP, WScale, SAckOK, Timestamp\n");
				opt_ts_offset = 2;
				// ts = (struct tcp_opt_ts*)(l4hdr + 20 + 10);
			}  
    	}
		else {
			DEBUG_PRINT("No Timestamp in options\n");
        	DEBUG_PRINT("Drop at router.h 259\n");
			return -1;
		}
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

#endif // ROUTER_H