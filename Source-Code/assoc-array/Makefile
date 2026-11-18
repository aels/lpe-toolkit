CC ?= gcc
OBJCOPY ?= objcopy
SRC := src
OUT ?= exploit

CFLAGS ?= -O2 -Wall -Wextra -std=gnu11 -pthread -fno-strict-aliasing
LDFLAGS ?= -static

export LC_ALL := C

CORE := $(SRC)/btf.c $(SRC)/layout.c $(SRC)/leak.c $(SRC)/target_gen.c

.PHONY: all install selftest layout leak clean

all: $(OUT)

# The capture stages are a second main() in the same binary; it is re-entered
# through k2_runtime_support_dispatch() so the probed layout, the page oracle
# and the retired-payload hand-off stay process-wide.
runtime_support_embedded.o: $(SRC)/runtime_support.c $(SRC)/public_helper_base.inc \
		$(SRC)/target_hardened.h $(SRC)/layout.h
	$(CC) $(CFLAGS) -I$(SRC) -Wno-parentheses -c $(SRC)/runtime_support.c -o $@.tmp
	$(OBJCOPY) --redefine-sym main=k2_runtime_support_dispatch $@.tmp $@
	rm -f $@.tmp

$(OUT): $(SRC)/exploit.c $(SRC)/race.inc $(SRC)/integrated_chain.inc \
		$(SRC)/freeptr.inc $(SRC)/target_gen.h $(SRC)/leak.h $(SRC)/btf.h \
		$(SRC)/layout.h $(SRC)/target_hardened.h $(CORE) \
		runtime_support_embedded.o
	$(CC) $(CFLAGS) -I$(SRC) -o $@ $(SRC)/exploit.c $(CORE) \
		runtime_support_embedded.o $(LDFLAGS)

# Drop the toolkit binary next to the dispatcher.
install: all
	cp $(OUT) ../../xpl2026/assoc-array-static
	chmod 0755 ../../xpl2026/assoc-array-static
	@echo "installed: ../../xpl2026/assoc-array-static"

selftest: all
	./$(OUT) --selftest

layout: all
	./$(OUT) --layout

leak: all
	./$(OUT) --leak-only

clean:
	rm -f $(OUT) runtime_support_embedded.o runtime_support_embedded.o.tmp
