BIN_TARGET = dlm_controld

MAN_TARGET = dlm_controld.8

HDR_TARGET = libdlmcontrol.h

LIB_NAME = libdlmcontrol
LIB_MAJOR = 3
LIB_MINOR = 1
LIB_SO = $(LIB_NAME).so
LIB_SMAJOR = $(LIB_SO).$(LIB_MAJOR)
LIB_TARGET = $(LIB_SO).$(LIB_MAJOR).$(LIB_MINOR)

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
BIN_CFLAGS += -I../include -I../libdlm

BIN_LDFLAGS += -Wl,-z,now -Wl,-z,relro -pie
BIN_LDFLAGS += `xml2-config --libs`
BIN_LDFLAGS += -lpthread -llogthread -lcpg -lconfdb -lcfg -lquorum -lfenced

LIB_SOURCE = lib.c
LIB_CFLAGS += $(BIN_CFLAGS)
LIB_LDFLAGS += -Wl,-z,relro -pie

all: $(LIB_TARGET) $(BIN_TARGET)

$(BIN_TARGET): $(BIN_SOURCE)
	$(CC) $(BIN_CFLAGS) $(BIN_LDFLAGS) $(BIN_SOURCE) -o $@ -L.

$(LIB_TARGET): $(LIB_SOURCE)
	$(CC) $(LIB_CFLAGS) $(LIB_LDFLAGS) -shared -fPIC -o $@ -Wl,-soname=$(LIB_SMAJOR) $^
	ln -sf $(LIB_TARGET) $(LIB_SO)
	ln -sf $(LIB_TARGET) $(LIB_SMAJOR)
	
clean:
	rm -f *.o *.so *.so.* $(BIN_TARGET)


INSTALL=$(shell which install)

DESTDIR=
BINDIR=/usr/sbin
LIBDIR=/usr/lib64
HDRDIR=/usr/include 
MANDIR=/usr/share/man

.PHONY: install
install: all
	$(INSTALL) -d $(DESTDIR)/$(BINDIR)
	$(INSTALL) -d $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -d $(DESTDIR)/$(HDRDIR)
	$(INSTALL) -d $(DESTDIR)/$(MANDIR)/man8
	$(INSTALL) -c -m 755 $(BIN_TARGET) $(DESTDIR)/$(BINDIR)
	$(INSTALL) -c -m 755 $(LIB_TARGET) $(DESTDIR)/$(LIBDIR)
	cp -a $(LIB_SO) $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -c -m 644 $(HDR_TARGET) $(DESTDIR)/$(HDRDIR)
	$(INSTALL) -m 644 $(MAN_TARGET) $(DESTDIR)/$(MANDIR)/man8/

