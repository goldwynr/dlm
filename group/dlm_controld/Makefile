TARGET = dlm_controld

SOURCE = \
	action.c \
	cpg.c \
	crc.c \
	main.c \
	plock.c \
	config.c \
	member_cman.c \
	logging.c \
	rbtree.c

CFLAGS += -D_GNU_SOURCE -g \
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

CFLAGS += -fPIE -DPIE
CFLAGS += `xml2-config --cflags`
CFLAGS += -I../include -I../../dlm/libdlm -I../../dlm/libdlmcontrol

LDFLAGS += -Wl,-z,now -Wl,-z,relro -pie
LDFLAGS += `xml2-config --libs`
LDFLAGS += -lpthread -llogthread -lcpg -lconfdb -lcfg -lquorum -lfenced

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SOURCE) -o $@ -L.

clean:
	rm -f *.o *.so *.so.* $(TARGET)

