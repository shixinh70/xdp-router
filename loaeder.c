#include <bpf/libbpf.h>
#include <bpf/bpf.h>


int main(){
    

    __u32 key;
    __u64 value_64;
    __u32 value_32;
    __u16 value_16;
    int fd = bpf_obj_get("/sys/fs/bpf/tc/globals/map_cookie_map_16");

    for (key = 0; key < 256; key++) {
            value_16 = (key << 2);
            bpf_map_update_elem(fd, &key, &value_16, BPF_ANY);
    }

    fd = bpf_obj_get("/sys/fs/bpf/tc/globals/map_cookie_map_32");
    
    for (key = 0; key < 256; key++) {
            value_32 = key + 32000;
            bpf_map_update_elem(fd, &key, &value_32, BPF_ANY);
    }

    fd = bpf_obj_get("/sys/fs/bpf/tc/globals/key_map");
    key = 0;
    value_64 = 0x1234567812345678;
    bpf_map_update_elem(fd,&key,&value_64,BPF_ANY);
    key=1;value_64=10;
    bpf_map_update_elem(fd,&key,&value_64,BPF_ANY);

}