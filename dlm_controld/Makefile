DESTDIR=
PREFIX=/usr
LIBNUM=/lib64
BINDIR=$(PREFIX)/sbin
LIBDIR=$(PREFIX)/$(LIBNUM)
HDRDIR=$(PREFIX)/include 
MANDIR=$(PREFIX)/share/man

USE_SD_NOTIFY=yes

BIN_TARGET = dlm_controld

LIB_NAME = libdlmcontrol
LIB_MAJOR = 3
LIB_MINOR = 1
LIB_SO = $(LIB_NAME).so
LIB_SMAJOR = $(LIB_SO).$(LIB_MAJOR)
LIB_TARGET = $(LIB_SO).$(LIB_MAJOR).$(LIB_MINOR)

BIN_SOURCE = action.c \
             cpg.c \
             daemon_cpg.c \
             crc.c \
             fence_config.c \
             fence.c \
             main.c \
             plock.c \
             config.c \
             member.c \
             logging.c \
             rbtree.c
LIB_SOURCE = lib.c

BIN_CFLAGS += -D_GNU_SOURCE -O2 -ggdb \
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
BIN_CFLAGS += -I../include -I../libdlm

BIN_LDFLAGS += -Wl,-z,now -Wl,-z,relro -pie
BIN_LDFLAGS += -lpthread -lrt -lcpg -lcmap -lcfg -lquorum

LIB_CFLAGS += $(BIN_CFLAGS)
LIB_LDFLAGS += -Wl,-z,relro -pie

ifeq ($(USE_SD_NOTIFY),yes)
	BIN_CFLAGS += $(shell pkg-config --cflags libsystemd-daemon) \
		      -DUSE_SD_NOTIFY
	BIN_LDFLAGS += $(shell pkg-config --libs libsystemd-daemon)
endif

all: $(LIB_TARGET) $(BIN_TARGET)

$(BIN_TARGET): $(BIN_SOURCE)
	$(CC) $(BIN_SOURCE) $(BIN_CFLAGS) $(BIN_LDFLAGS) -o $@ -L.

$(LIB_TARGET): $(LIB_SOURCE)
	$(CC) $^ $(LIB_CFLAGS) $(LIB_LDFLAGS) -shared -fPIC -o $@ -Wl,-soname=$(LIB_SMAJOR)
	ln -sf $(LIB_TARGET) $(LIB_SO)
	ln -sf $(LIB_TARGET) $(LIB_SMAJOR)

clean:
	rm -f *.o *.so *.so.* $(BIN_TARGET) $(LIB_TARGET)


INSTALL=$(shell which install)

.PHONY: install
install: all
	$(INSTALL) -d $(DESTDIR)/$(BINDIR)
	$(INSTALL) -d $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -d $(DESTDIR)/$(HDRDIR)
	$(INSTALL) -d $(DESTDIR)/$(MANDIR)/man8
	$(INSTALL) -d $(DESTDIR)/$(MANDIR)/man5
	$(INSTALL) -m 755 $(BIN_TARGET) $(DESTDIR)/$(BINDIR)
	$(INSTALL) -m 755 $(LIB_TARGET) $(DESTDIR)/$(LIBDIR)
	cp -a $(LIB_SO) $(DESTDIR)/$(LIBDIR)
	cp -a $(LIB_SMAJOR) $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -m 644 libdlmcontrol.h $(DESTDIR)/$(HDRDIR)
	$(INSTALL) -m 644 dlm_controld.8 $(DESTDIR)/$(MANDIR)/man8/
	$(INSTALL) -m 644 dlm.conf.5 $(DESTDIR)/$(MANDIR)/man5/

