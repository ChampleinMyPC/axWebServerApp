PROG1 = $(shell jq -r '.acapPackageConf.setup.appName' manifest.json)
OBJS1 = $(PROG1).c
PROGS = $(PROG1)
LIBDIR = lib
DEBUG_DIR = debug

PKGS = glib-2.0

LDLIBS += -lcivetweb
LDLIBS += -lcurl
CFLAGS += -I/opt/build/civetweb/include
CFLAGS += -DUSE_WEBSOCKET

CFLAGS += $(shell pkg-config --cflags $(PKGS))

LDFLAGS += -L$(LIBDIR) -Wl,--no-as-needed,-rpath,'$$ORIGIN/lib'
CFLAGS += $(shell pkg-config --cflags glib-2.0 gio-2.0)
CFLAGS += -I$(SDKTARGETSYSROOT)/usr/include/axsdk

# LDFLAGS += -Llib -Wl,--no-as-needed,-rpath,'$$ORIGIN/lib'
LDLIBS  += -lcivetweb -lcurl -lm \
           $(shell pkg-config --libs glib-2.0 gio-2.0 gobject-2.0) \
           -laxstorage

CFLAGS += -Wall \
          -Wextra \
          -Wformat=2 \
          -Wpointer-arith \
          -Wbad-function-cast \
          -Wstrict-prototypes \
          -Wmissing-prototypes \
          -Winline \
          -Wdisabled-optimization \
          -Wfloat-equal \
          -W \
          -Werror

all:	$(PROGS)

$(PROG1): $(OBJS1)
	install -d $(DEBUG_DIR)
	$(CC) $^ $(CFLAGS) $(LIBS) $(LDFLAGS) -lm $(LDLIBS) -o $(DEBUG_DIR)/$@
	cp $(DEBUG_DIR)/$@ .
	$(STRIP) $@

clean:
	rm -rf $(PROGS) *.o *.eap* *_LICENSE.txt package.conf* param.conf tmp* $(LIBDIR) $(DEBUG_DIR)
