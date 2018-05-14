bin_PROGRAMS = sniff2ban
sniff2ban_SOURCES = hashtable.c sniff2ban.c
# sniff2ban_LDADD = -lm -lpcap -lresolv

install: $(bin_PROGRAMS)
	mv $< /usr/local/sbin/$<
	chown root /usr/local/sbin/$<
	chmod 744 /usr/local/sbin/$<
