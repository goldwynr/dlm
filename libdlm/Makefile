DESTDIR=
PREFIX=/usr
LIBNUM=/lib64
LIBDIR=$(PREFIX)/$(LIBNUM)
HDRDIR=$(PREFIX)/include 
MANDIR=$(PREFIX)/share/man
PKGDIR=$(LIBDIR)/pkgconfig
UDEVDIR=/lib/udev/rules.d

LIB_NAME = libdlm
LIB_MAJOR = 3
LIB_MINOR = 0
LIB_O = $(LIB_NAME).o
LIB_SO = $(LIB_NAME).so
LIB_SMAJOR = $(LIB_SO).$(LIB_MAJOR)
LIB_TARGET = $(LIB_SO).$(LIB_MAJOR).$(LIB_MINOR)
LIB_PC = $(LIB_NAME).pc
LIB_PCIN = $(LIB_NAME).pc.in

LLT_NAME = libdlm_lt
LLT_MAJOR = 3
LLT_MINOR = 0
LLT_O = $(LLT_NAME).o
LLT_SO = $(LLT_NAME).so
LLT_SMAJOR = $(LLT_SO).$(LLT_MAJOR)
LLT_TARGET = $(LLT_SO).$(LLT_MAJOR).$(LLT_MINOR)
LLT_PC = $(LLT_NAME).pc
LLT_PCIN = $(LLT_NAME).pc.in

HDR_TARGET = libdlm.h

MAN_TARGET = \
	man/dlm_cleanup.3 \
	man/dlm_close_lockspace.3 \
	man/dlm_create_lockspace.3 \
	man/dlm_dispatch.3 \
	man/dlm_get_fd.3 \
	man/dlm_lock.3 \
	man/dlm_lock_wait.3 \
	man/dlm_ls_lock.3 \
	man/dlm_ls_lock_wait.3 \
	man/dlm_ls_lockx.3 \
	man/dlm_ls_pthread_init.3 \
	man/dlm_ls_unlock.3 \
	man/dlm_ls_unlock_wait.3 \
	man/dlm_new_lockspace.3 \
	man/dlm_open_lockspace.3 \
	man/dlm_pthread_init.3 \
	man/dlm_release_lockspace.3 \
	man/dlm_unlock.3 \
	man/dlm_unlock_wait.3 \
	man/libdlm.3

UDEV_TARGET = 51-dlm.rules

SOURCE = libdlm.c

CFLAGS += -D_GNU_SOURCE -O2 -ggdb \
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
	-fPIC

LIB_CFLAGS += $(CFLAGS) -D_REENTRANT
LLT_CFLAGS += $(CFLAGS)

LIB_LDFLAGS += $(LDFLAGS) -lpthread
LLT_LDFLAGS += $(LDFLAGS)

all: $(LIB_TARGET) $(LLT_TARGET) $(LIB_PC) $(LLT_PC)

$(LIB_O): $(SOURCE) 
	$(CC) $< $(LIB_CFLAGS) -c -o $@

$(LLT_O): $(SOURCE) 
	$(CC) $< $(LLT_CFLAGS) -c -o $@

$(LIB_TARGET): $(LIB_O)
	$(CC) $^ $(LIB_LDFLAGS) -shared -o $@ -Wl,-soname=$(LIB_SMAJOR)
	ln -sf $(LIB_TARGET) $(LIB_SO)
	ln -sf $(LIB_TARGET) $(LIB_SMAJOR)

$(LLT_TARGET): $(LLT_O)
	$(CC) $^ $(LLT_LDFLAGS) -shared -o $@ -Wl,-soname=$(LLT_SMAJOR)
	ln -sf $(LLT_TARGET) $(LLT_SO)
	ln -sf $(LLT_TARGET) $(LLT_SMAJOR)

$(LIB_PC): $(LIB_PCIN)
	cat $(LIB_PCIN) | sed -e 's#@PREFIX@#$(PREFIX)#g' > $@

$(LLT_PC): $(LLT_PCIN)
	cat $(LIB_PCIN) | sed -e 's#@PREFIX@#$(PREFIX)#g' > $@

clean:
	rm -f *.o *.so *.so.* *.a *.pc

INSTALL=$(shell which install)

.PHONY: install
install: all
	$(INSTALL) -d $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -d $(DESTDIR)/$(HDRDIR)
	$(INSTALL) -d $(DESTDIR)/$(MANDIR)/man3
	$(INSTALL) -d $(DESTDIR)/$(PKGDIR)
	$(INSTALL) -d $(DESTDIR)/$(UDEVDIR)
	$(INSTALL) -c -m 755 $(LIB_TARGET) $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -c -m 755 $(LLT_TARGET) $(DESTDIR)/$(LIBDIR)
	cp -a $(LIB_SO) $(DESTDIR)/$(LIBDIR)
	cp -a $(LIB_SMAJOR) $(DESTDIR)/$(LIBDIR)
	cp -a $(LLT_SO) $(DESTDIR)/$(LIBDIR)
	cp -a $(LLT_SMAJOR) $(DESTDIR)/$(LIBDIR)
	$(INSTALL) -m 644 $(LIB_PC) $(DESTDIR)/$(PKGDIR)
	$(INSTALL) -m 644 $(LLT_PC) $(DESTDIR)/$(PKGDIR)
	$(INSTALL) -c -m 644 $(HDR_TARGET) $(DESTDIR)/$(HDRDIR)
	$(INSTALL) -m 644 $(MAN_TARGET) $(DESTDIR)/$(MANDIR)/man3/
	$(INSTALL) -m 644 $(UDEV_TARGET) $(DESTDIR)/$(UDEVDIR)

