BIN_TARGET = dlm_controld
MAN_TARGET = dlm_controld.8

BIN_SOURCE = \
	action.c \
	cpg.c \
	crc.c \
	main.c \
	plock.c \
	config.c \
	member_cman.c \
	logging.c \
	rbtree.c

BIN_CFLAGS += -D_GNU_SOURCE -g \
	-Wall \
	-Wformat \
	-Wformat-security \
	-Wmissing-prototypes \
	-Wnested-externs \
	-Wpointer-arith \
	-Wextra -Wshadow \
	-Wcast-align \
	-Wwrite-strings \
	-Waggregate-return \
	-Wstrict-prototypes \
	-Winline \
	-Wredundant-decls \
	-Wno-sign-compare \
	-Wno-unused-parameter \
	-Wp,-D_FORTIFY_SOURCE=2 \
	-fexceptions \
	-fasynchronous-unwind-tables \
	-fdiagnostics-show-option \

BIN_CFLAGS += -fPIE -DPIE
BIN_CFLAGS += `xml2-config --cflags`
BIN_CFLAGS += -I../dlm/libdlm -I../dlm/libdlmcontrol

BIN_LDFLAGS += -Wl,-z,now -Wl,-z,relro -pie
BIN_LDFLAGS += `xml2-config --libs`
BIN_LDFLAGS += -lpthread -llogthread -lcpg -lconfdb -lcfg -lquorum -lfenced

all: $(BIN_TARGET)

$(BIN_TARGET): $(BIN_SOURCE)
	$(CC) $(BIN_CFLAGS) $(BIN_LDFLAGS) $(BIN_SOURCE) -o $@ -L.

clean:
	rm -f *.o *.so *.so.* $(BIN_TARGET)


INSTALL=$(shell which install)

DESTDIR=
BINDIR=/usr/sbin
MANDIR=/usr/share/man

.PHONY: install
install: all
	$(INSTALL) -d $(DESTDIR)/$(BINDIR)
	$(INSTALL) -d $(DESTDIR)/$(MANDIR)/man8
	$(INSTALL) -c -m 755 $(BIN_TARGET) $(DESTDIR)/$(BINDIR)
	$(INSTALL) -m 644 $(MAN_TARGET) $(DESTDIR)/$(MANDIR)/man8/

