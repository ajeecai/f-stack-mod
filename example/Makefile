TOPDIR=..

ifeq ($(FF_PATH),)
	FF_PATH=${TOPDIR}
endif

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "No installation of DPDK found, maybe you should export environment variable `PKG_CONFIG_PATH`")
endif

PKGCONF ?= pkg-config

CFLAGS += -O0 -g -gdwarf-2 $(shell $(PKGCONF) --cflags libdpdk)

LIBS+= $(shell $(PKGCONF) --static --libs libdpdk)
LIBS+= -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-whole-archive
LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -lssl -pthread -lnuma

ANET_IF_OBJ=anet_ff.o

TARGET="helloworld"
all:$(ANET_IF_OBJ)
	cc ${CFLAGS} -DINET6 -o ${TARGET}_ssl main_ssl.c $(ANET_IF_OBJ) ${LIBS}
	cc ${CFLAGS} -DINET6 -o ${TARGET} main.c ${LIBS}
	cc ${CFLAGS} -o ${TARGET}_epoll main_epoll.c ${LIBS}

$(ANET_IF_OBJ):
	cc ${CFLAGS} -c -DINET6 ../app/redis-6.2.6/src/anet_ff.c

.PHONY: clean
clean:
	rm -f *.o ${TARGET} ${TARGET}_epoll
