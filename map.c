#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

#define COOKI_MAP_ENTRY 256
void init_map_cookie_map_16(int fd){
    __u32 key; __u16 val;
    for (key = 0; key < COOKI_MAP_ENTRY; key++) {
            val = rand() & 0xffff;
            if(bpf_map_update_elem(fd, &key, &val, BPF_ANY) < 0){
                fprintf(stderr,"bpf_map_update_elem fail\n");
                exit(EXIT_FAILURE);
            }
    }
}
void init_map_cookie_map_32(int fd){
    __u32 key; __u32 val;
    for (key = 0; key < COOKI_MAP_ENTRY; key++) {
            val = rand();
            if(bpf_map_update_elem(fd, &key, &val, BPF_ANY) < 0){
                fprintf(stderr,"bpf_map_update_elem fail\n");
                exit(EXIT_FAILURE);
                
            }
    }
}
void init_key_map(int fd){
    __u32 key; __u64 val;
    key = 0; val = rand();
    if(bpf_map_update_elem(fd, &key, &val, BPF_ANY) < 0){
        fprintf(stderr,"bpf_map_update_elem fail\n");
        exit(EXIT_FAILURE);
        
    }
    key = 1; val = 10;
    if(bpf_map_update_elem(fd, &key, &val, BPF_ANY) < 0){
        fprintf(stderr,"bpf_map_update_elem fail\n");
        exit(EXIT_FAILURE);
        
    }

} 



void print_map(int map, int fd){
    __u64 val = 0; __u32 key = 0;
    if(map == 1 || map ==2 ){
        for(key=0;key<COOKI_MAP_ENTRY;key++){    
            bpf_map_lookup_elem(fd, &key, &val);
            printf("map_cookie_map_%u [%u] : %llu\n", map*16, key, val);       
        }
    }
    else{
        key = 0;
        if(bpf_map_lookup_elem(fd, &key, &val)<0){
            fprintf(stderr,"WARN: Failed to lookup bpf elem:err(%d):%s\n", errno, strerror(errno));
            exit(EXIT_FAILURE);
        }
        printf("key_map [0](hash_key) : 0x%llX\n",val);
        val = 0;key =1;
        if(bpf_map_lookup_elem(fd, &key, &val)<0){
            fprintf(stderr,"WARN: Failed to lookup bpf elem:err(%d):%s\n", errno, strerror(errno));
            exit(EXIT_FAILURE);
        }
        printf("key_map [1](divide_key) : %llu\n",val);
    }
}
void modify_map(int map, int fd, __u32 key, __u64 val){
        if(bpf_map_update_elem(fd, &key, &val, BPF_ANY) < 0){
                fprintf(stderr,"bpf_map_update_elem fail\n");
                exit(EXIT_FAILURE);
        }
        val = 0;
        if(bpf_map_lookup_elem(fd, &key, &val)<0){
            fprintf(stderr,"WARN: Failed to lookup bpf elem:err(%d):%s\n", errno, strerror(errno));
            exit(EXIT_FAILURE);
        }
        printf("New entry of MAP(%d)[%u] : %llu\n",map,key,val);
    
}

int main() {

    int fd1 = bpf_obj_get("/sys/fs/bpf/tc/globals/map_cookie_map_16");
    if(fd1 < 0 ){
        fprintf(stderr,"WARN: Failed to open bpf map file: map_cookie_map_16 err(%d):%s\n", errno, strerror(errno));
        exit(EXIT_FAILURE);
        
    }
    int fd2 = bpf_obj_get("/sys/fs/bpf/tc/globals/map_cookie_map_32");
    if(fd2 < 0 ){
        fprintf(stderr,"WARN: Failed to open bpf map file: map_cookie_map_32 err(%d):%s\n", errno, strerror(errno));
        exit(EXIT_FAILURE);
    
    }
    int fd3 = bpf_obj_get("/sys/fs/bpf/tc/globals/key_map");
    if(fd3 < 0 ){
        fprintf(stderr,"WARN: Failed to open bpf map file: key_map err(%d):%s\n", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }


    while (1) {
        printf("[1] initial map\n[2] cat map\n[3] modify map\n");
        int seed;
        int choice;
        printf("Enter your choice: ");
        scanf("%d", &choice);
        
        int map;
        __u32 key; __u64 val;
        switch (choice) {
            case 1:
                printf("Enter your random seed\n");
                if(scanf("%d",&seed) < 0){
                    fprintf(stderr,"WARN: Failed to scanf seed: key_map \n");
                }
                srand(seed);
                init_map_cookie_map_16(fd1);
                init_map_cookie_map_32(fd2);
                init_key_map(fd3);
                printf("Maps initialized successfully!\n");
                break;
            case 2:
                
                printf("Choose map to cat\n");
                printf("[1] map_cookie_map_16\n[2] map_cookie_map_32\n[3] key_map\n");
                if(scanf("%d",&map) < 0){
                    fprintf(stderr,"WARN: Failed to scanf map: key_map \n");
                }
                switch (map){
                    case 1:
                        print_map(map,fd1);
                        break;
                    case 2:
                        print_map(map,fd2);
                        break;
                    case 3:
                        print_map(map,fd3);
                        break;
                    default:
                    printf("Invalid choice\n");
                }

                break;
            case 3:
                
                printf("Choose map to modify\n");
                printf("[1] map_cookie_map_16\n[2] map_cookie_map_32\n[3] key_map\n");
                printf("Enter MAP KEY VALUE, ex: 1 234 1882\n");
                if(scanf("%d %d %llu",&map, &key, &val) != 3){
                    fprintf(stderr,"WARN: Failed to scanf map key val\n");
                }
                
                
                switch (map){
                    case 1:
                        modify_map(map,fd1,key,val);
                    break;
                    case 2:
                        modify_map(map,fd2,key,val);
                    break;
                    case 3:
                        modify_map(map,fd3,key,val);
                    break;
                }

                break;
            default:
                printf("Invalid choice\n");
        }
    }

   return 0;
}