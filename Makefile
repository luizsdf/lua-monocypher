PREFIX = /usr/local
LUA_VERSION = 5.1
LUA_LIBDIR = $(DESTDIR)$(PREFIX)/lib/lua/$(LUA_VERSION)
LUA_INCDIR = $(PREFIX)/include/lua$(LUA_VERSION)

CFLAGS = -Wall -Wextra -O2 -fPIC -I$(LUA_INCDIR)
LDFLAGS = -shared
#LDFLAGS = -bundle -undefined dynamic_lookup # MacOSX
OBJ = lua-monocypher.o monocypher.o monocypher-ed25519.o

all: monocypher.so

.c.o:
	$(CC) $(CFLAGS) -c $<

monocypher.so: $(OBJ)
	$(LD) $(LDFLAGS) -o $@ $(OBJ)

install: monocypher.so
	mkdir -p $(LUA_LIBDIR)
	cp -f monocypher.so $(LUA_LIBDIR)
	chmod 755 $(LUA_LIBDIR)/monocypher.so

uninstall:
	rm -f $(LUA_LIBDIR)/monocypher.so

clean:
	rm -f monocypher.so $(OBJ)

.PHONY: all install uninstall clean
