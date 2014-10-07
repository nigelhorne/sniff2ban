bin_PROGRAMS = clsniffer
clsniffer_SOURCES = hashtable.c clamav-sniffer.c
# clsniffer_LDADD = -lm -lpcap -lresolv

install: $(bin_PROGRAMS)
	mv $< /usr/local/sbin/$<
	chown root /usr/local/sbin/$<
	chmod 744 /usr/local/sbin/$<
