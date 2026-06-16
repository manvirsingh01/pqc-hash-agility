# This Makefile can be used with GNU Make or BSD Make

LIB=libml-kem-1024_turboshake.a
HEADERS=api.h cbd.h indcpa.h kem.h ntt.h params.h poly.h polyvec.h reduce.h symmetric.h verify.h
OBJECTS=cbd.o indcpa.o kem.o ntt.o poly.o polyvec.o reduce.o symmetric-turboshake.o verify.o

CFLAGS=-O3 -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -std=c99 \
       -I../../../common -I/root/XKCP/bin/generic64/libXKCP.a.headers $(EXTRAFLAGS)

all: $(LIB)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJECTS)
	$(AR) -r $@ $(OBJECTS)

clean:
	$(RM) $(OBJECTS)
	$(RM) $(LIB)
