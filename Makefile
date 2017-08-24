bindir = /usr/local/bin
man1dir = /usr/local/share/man/man1

CFLAGS = -std=c11 -Wall -pedantic -g -O3
CFLAGS_ALL = `pkg-config --cflags --libs glib-2.0 x11 xscrnsaver dbus-1` $(CFLAGS)

.PHONY: all
all: xssproxy xssproxy.1.gz

xssproxy: xssproxy.c
	$(CC) -o xssproxy xssproxy.c $(CFLAGS_ALL) $(CPPFLAGS) $(LDFLAGS)

xssproxy.1.gz: man/xssproxy.1
	gzip -c man/xssproxy.1 > xssproxy.1.gz

install: xssproxy xssproxy.1.gz
	install -D xssproxy $(DESTDIR)$(bindir)/xssproxy
	install -D -m644 xssproxy.1.gz $(DESTDIR)$(man1dir)/xssproxy.1.gz

.PHONY: uninstall
uninstall:
	$(RM) $(DESTDIR)$(bindir)/xssproxy
	$(RM) $(DESTDIR)$(man1dir)/xssproxy.1.gz

.PHONY: clean
clean:
	$(RM) xssproxy
	$(RM) xssproxy.1.gz
