#include "fnv.h"
#include "murmur2.h"
#include <time.h>
#include <stdio.h>
#include <stdint.h>

#define SIPROUND          \
	do                    \
	{                     \
		v0 += v1;         \
		v2 += v3;         \
		v1 = rol(v1, 5);  \
		v3 = rol(v3, 8);  \
		v1 ^= v0;         \
		v3 ^= v2;         \
		v0 = rol(v0, 16); \
		v2 += v1;         \
		v0 += v3;         \
		v1 = rol(v1, 13); \
		v3 = rol(v3, 7);  \
		v1 ^= v2;         \
		v3 ^= v0;         \
		v2 = rol(v2, 16); \
	} while (0)

const int key0 = 0x33323130;
const int key1 = 0x42413938;
const int c0 = 0x70736575;
const int c1 = 0x6e646f6d;
const int c2 = 0x6e657261;
const int c3 = 0x79746573;

static inline uint32_t rol(uint32_t word, uint32_t shift)
{
	return (word << shift) | (word >> (32 - shift));
}

static __always_inline uint32_t get_hash(uint32_t* src)
{

	// initialization
	int v0 = c0 ^ key0;
	int v1 = c1 ^ key1;
	int v2 = c2 ^ key0;
	int v3 = c3 ^ key1;

	// first message
	v3 = v3 ^ (*src);
	SIPROUND;
	SIPROUND;
	v0 = v0 ^ (*src);

	// // second message
	// v3 = v3 ^ bpf_ntohl(dst);
	// SIPROUND;
	// SIPROUND;
	// v0 = v0 ^ bpf_ntohl(dst);

	// // third message
	// uint32_t ports = (uint32_t)dst_port << 16 | (uint32_t)src_port;
	// v3 = v3 ^ bpf_ntohl(ports);
	// SIPROUND;
	// SIPROUND;
	// v0 = v0 ^ bpf_ntohl(ports);

	// finalization
	v2 = v2 ^ 0xFF;
	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;

	uint32_t hash = (v0 ^ v1) ^ (v2 ^ v3);
	//hash %= bpf_htonl(0x80000000);
	return hash;
}

unsigned long djb2(unsigned char *str)
    {
        unsigned long hash = 5381;
        int c;

        while (c = *str++)
            hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

        return hash;
    }
unsigned long djb2a(unsigned char *str)
    {
        unsigned long hash = 5381;
        int c;

        while (c = *str++)
            hash = ((hash << 5) + hash) ^ c; /* hash * 33 + c */

        return hash;
    }
static unsigned long sdbm(unsigned char *str) 
    {
        unsigned long hash = 0;
        int c;

        while (c = *str++)
            hash = c + (hash << 6) + (hash << 16) - hash;

        return hash;
    }

static unsigned long sdbma(unsigned char *str) 
    {
        unsigned long hash = 0;
        int c;

        while (c = *str++)
            hash = c ^ (hash << 6) ^ (hash << 16) - hash;

        return hash;
    }

int main (){
    int bucket[65536] = {0};
    clock_t begin = clock();
    for(uint32_t i=0;i<UINT32_MAX;i++){
        uint32_t h = get_hash(&i);
        h = (h>>16) ^ ((h << 16)>>16);
        bucket[h] ++;
    }
    clock_t end = clock();
    double time_spent = (double)(end - begin) * 1000; //nano sec;
    time_spent /= UINT32_MAX;
    int count = 0;
    for(int i = 0; i<65536;i++){
        if(bucket[i] == 65536)
            count ++;
        printf("bucket[%d] = %d ", i , bucket[i]);
    }
    printf("count = %d\n",count);
    printf("Time spend (ns) = %f\n",time_spent);
   

}