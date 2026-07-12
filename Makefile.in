include config.mk

SECP = deps/secp256k1
DEFS = -DENABLE_MODULE_SCHNORRSIG -DENABLE_MODULE_EXTRAKEYS \
	-DUSE_TCL_STUBS $(EXTRA_DEFS)
CFLAGS = -O2 -Wall
CPPFLAGS = -I$(SECP)/include -Ivendor $(TCL_INCLUDE_SPEC) $(DEFS)

VPATH = vendor:$(SECP)/src

SRCS = tclnostr.c rand.c sha256.c bech32.c \
	secp256k1.c precomputed_ecmult.c precomputed_ecmult_gen.c
OBJS = $(SRCS:%.c=build/s/%.o)
POBJS = $(SRCS:%.c=build/p/%.o)

all: libnostr.a $(SHARED)

libnostr.a: $(OBJS)
	$(AR) cr $@ $(OBJS)
	$(RANLIB) $@

libnostr.so: $(POBJS)
	$(CC) -shared -o $@ $(POBJS) $(TCL_STUB_LIB_SPEC)

build/s/%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

build/p/%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -fPIC -c -o $@ $<

test: $(SHARED)
	$(TCLSH) tests/all.tcl

clean:
	rm -rf build/s/*.o build/p/*.o libnostr.a libnostr.so

.PHONY: all test clean
