DESTDIR=
PREFIX=/usr
LIBNUM=/lib64
BINDIR=$(PREFIX)/sbin
LIBDIR=$(PREFIX)/$(LIBNUM)
HDRDIR=$(PREFIX)/include 
MANDIR=$(PREFIX)/share/man
INITDIR=/etc/init.d
UNITDIR=/lib/systemd/system

BIN_TARGET = dlm_controld
MAN_TARGET = dlm_controld.8
HDR_TARGET = libdlmcontrol.h
INIT_TARGET = dlm
UNIT_TARGET = dlm.service

LIB_NAME = libdlmcontrol
LIB_MAJOR = 3
LIB_MINOR = 1
LIB_SO = $(LIB_NAME).so
LIB_SMAJOR = $(LIB_SO).$(LIB_MAJOR)
LIB_TARGET = $(LIB_SO).$(LIB_MAJOR).$(LIB_MINOR)

BIN_SOURCE = action.c \
             cpg.c \
             crc.c \
             fence.c \
             main.c \
             plock.c \
             config.c \
             member.c \
             logging.c \
             rbtree.c
LIB_SOURCE = lib.c
INIT_SOURCE = dlm.in
UNIT_SOURCE = dlm.service.in

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
BIN_LDFLAGS += -lpthread -lrt -lcpg -lcmap -lcfg -lquorum
#BIN_LDFLAGS += -lfenced

LIB_CFLAGS += $(BIN_CFLAGS)
LIB_LDFLAGS += -Wl,-z,relro -pie

all: $(LIB_TARGET) $(BIN_TARGET) $(INIT_TARGET) $(UNIT_TARGET)

$(BIN_TARGET): $(BIN_SOURCE)
	$(CC) $(BIN_CFLAGS) $(BIN_LDFLAGS) $(BIN_SOURCE) -o $@ -L.

$(LIB_TARGET): $(LIB_SOURCE)
	$(CC) $(LIB_CFLAGS) $(LIB_LDFLAGS) -shared -fPIC -o $@ -Wl,-soname=$(LIB_SMAJOR) $^
	ln -sf $(LIB_TARGET) $(LIB_SO)
	ln -sf $(LIB_TARGET) $(LIB_SMAJOR)

$(INIT_TARGET): $(INIT_SOURCE)
	cp $(INIT_SOURCE) $(INIT_TARGET)

$(UNIT_TARGET): $(UNIT_SOURCE)
	cp $(UNIT_SOURCE) $(UNIT_TARGET)
	
clean:
	rm -f *.o *.so *.so.* $(BIN_TARGET) $(LIB_TARGET) $(INIT_TARGET) $(UNIT_TARGET)


INSTALL=$(shell which install)

.PHONY: install
install: all
	$(INSTALL) -d $(DESTDIR)/$(BINDIR)
	$(INSTALL) -d $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -d $(DESTDIR)/$(HDRDIR)
	$(INSTALL) -d $(DESTDIR)/$(INITDIR)
	$(INSTALL) -d $(DESTDIR)/$(UNITDIR)
	$(INSTALL) -d $(DESTDIR)/$(MANDIR)/man8
	$(INSTALL) -c -m 755 $(BIN_TARGET) $(DESTDIR)/$(BINDIR)
	$(INSTALL) -c -m 755 $(LIB_TARGET) $(DESTDIR)/$(LIBDIR)
	cp -a $(LIB_SO) $(DESTDIR)/$(LIBDIR)
	cp -a $(LIB_SMAJOR) $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -c -m 644 $(HDR_TARGET) $(DESTDIR)/$(HDRDIR)
	$(INSTALL) -m 755 $(INIT_TARGET) $(DESTDIR)/$(INITDIR)
	$(INSTALL) -m 755 $(UNIT_TARGET) $(DESTDIR)/$(UNITDIR)
	$(INSTALL) -m 644 $(MAN_TARGET) $(DESTDIR)/$(MANDIR)/man8/

