LLC ?= llc
CLANG ?= clang
CC ?= gcc

LIBBPF_DIR = libbpf/src
LIBBPF = $(LIBBPF_DIR)/libbpf.a

CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -g
CFLAGS += -I../headers/
LDFLAGS ?= -L$(LIBBPF_DIR)

LIBS = -l:libbpf.a -lelf

BPF_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -I../headers/
BPF_CFLAGS += -Wall -Wextra

.PHONY: all clean

all: router.o server_in.o hping_ts.o server_en.o

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean

$(LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "libbpf not found, try \`git submodule update --init'"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all; \
		mkdir -p build; DESTDIR=build $(MAKE) install_headers; \
	fi

router.o: router.c router.h $(LIBBPF)
	$(CLANG) -S -target bpf $(BPF_CFLAGS) -O3 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

server_in.o: server_in.c router.h $(LIBBPF)
	$(CLANG) -S -target bpf $(BPF_CFLAGS) -O3 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

hping_ts.o: hping_ts.c router.h $(LIBBPF)
	$(CLANG) -S -target bpf $(BPF_CFLAGS) -O3 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

server_en.o: server_en.c router.h $(LIBBPF)
	$(CLANG) -S -target bpf $(BPF_CFLAGS) -O3 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}