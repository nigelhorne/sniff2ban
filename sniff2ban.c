/*
 *  sniff2ban.c: Scan for intrusions
 *
 *  Copyright (C) 2009-2024 Nigel Horne, njh@bandsman.co.uk
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 *
 * This program does not need to be thread safe
 *
 * TODO: more error checking
 * TODO: Handle TCP packets out of order and/or fragmented (libpcap may do
 *		this already) and sequence numbers
 * TODO: Consider netfilter/ULOG on Linux
 * TODO: Support UDP
 * TODO: Connect to spamassassin (probably not needed if you use Sanesecurity)
 * FIXME: On Solaris10 I see "too many open files" errors.
 * TODO: Handle background/foreground by enabling/disabling promiscuous mode
 * TODO: --enable-http-scanning should be a runtime not a compile time option
 * TODO: condsider libipq (iptables-dev on Debian)
 * TODO: use INSTREAM when talking to clamd, and stop creating the temp files
 * TODO: to avoid clamd timeout and dropping the IDSESSION, send PING from time
 *	to time
 * TODO: SMTP_SCANNING - look for 'possible SMTP attack'
 *
 * Version 0.07 21/12/09
 * Version 0.10 12/2/10
 */
/* RFC791 = IP */
/* RFC793 = TCP */

#if	HAVE_CONFIG_H
#include "config.h"
#endif

/* no LIBPCAP (raw mode) only works on Linux */
#if	!defined(C_LINUX) && !defined(HAVE_LIBPCAP)
#error	You must install libpcap
#endif

#define	_GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <net/if.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IP_COMPAT_H
#include <netinet/ip_compat.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif
#ifdef HAVE_NET_IF_ETHER_H
#include <net/if_ether.h>
#endif
#ifdef HAVE_SYS_ETHERNET_H
#include <sys/ethernet.h>
#endif
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#include <netinet/ip.h>
#include <netinet/tcp.h>
#ifdef	HAVE_LIBPCAP
#include <pcap.h>
#endif
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <fcntl.h>
#include <time.h>
#include <syslog.h>
#include <getopt.h>
#include <ctype.h>
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#ifdef	HAVE_RESOLV_H
#include <resolv.h>
#endif
#include <assert.h>
#include <dirent.h>
#include "hashtable.h"

#define	MAXBYTES	2048
#ifdef SITES_ENABLED_DIR
#define	MINSCANSIZE	8
#else
#define	MINSCANSIZE	64
#endif
#define	MAXSCANSIZE	1024L*1024L
#define	TIMEALIVE	60	/*
				 * After this number of seconds assume the
				 * connection has closed
				 */
#define	MIN_SCAN_OFTEN_SECS	5	/* Do not scan a file more often than this */
#if(defined(AUTH_LOG) || defined(DOVECOT_LOG))
#define	MAX_FAILURES	3	/* Any more than this and you can't get in */
#endif

union ip_addr {
	in_addr_t	i;
	unsigned	char c[4];
};

struct key {
	union	ip_addr	saddr;
	union	ip_addr	daddr;
	in_port_t	sport;
	in_port_t	dport;
};

struct value {
	char	*filename;
	off_t	nbytes;
	time_t	lastscanned;
	time_t	lastwritten;
	unsigned	int	infected:1;
	unsigned	int	forcescan:1;
	FILE	*fp;
};

static	struct whitelist {
	union	ip_addr	addr;
	uint32_t	mask;
	struct	whitelist	*next;
} *whitelist, *whitelist_tail;

static	struct sacredlist {
	const	char	*program;
	struct	sacredlist	*next;
} *sacredlist, *sacredlist_tail;

#ifdef SITES_ENABLED_DIR
static	struct apachehosts {
	const	char	*name;
	struct	apachehosts	*next;
} *apachehosts;
#endif

#ifdef	CLAMD_CONF
static	const	char	*sockname;	/* talk to clamd: pathname or host */
static	in_port_t	sockport;	/* talk to clamd: if host */
static	int	clamd_socket;
#endif

#ifdef SITES_ENABLED_DIR
/*
 * This blocks legitimate access to services such as phpmyadmin and
 * crossdomain.xml, but you can get around that by whitelisting the client
 */
static	const	char	*http_probes[] = {
	"GET //mysql/",
	"GET /mysql//scripts/setup.php",
	"GET /admin/mysql/scripts/setup.php",
	"GET /user/soapCaller.bs",
	"GET /w00tw00t.at.",
	"GET /test.w00t:)",
	/*"GET /w00tw00t.at.ISC.SANS.DFind:)",*/
	/*"GET /w00tw00t.at.blackhats.romanian.anti-sec:)",*/
	"GET /pma//scripts/setup.php",
	"GET /pma/scripts/setup.php",
	"HEAD /pma/scripts/setup.php",
	"GET //zencart//install.txt",
	"GET /horde//README",	/* Mambo */
	"GET /cube/README",	/* Morfeus */
	"GET /roundcubemail/README",	/* Morfeus */
	"GET /round/README",	/* Morfeus */
	"GET //phpMyAdmin//scripts/setup.php",
	"GET /phpmyadmin/scripts/setup.php", /* Toata dragostea mea pentru iEdi */
	"GET //phpmyadmin/",
	"GET /phpmyadmin//scripts/setup.php",
	"GET /phpmyadmin/scripts/setup.php",
	"GET //phpmyadmin/config/config.inc.php?p=phpinfo();",
	"GET /phpMyAdmin-",	/* ZmEu */
	"GET //phpMyAdmin/",
	"GET /phpMyAdmin/",
	"GET /phpMyAdmin-2.10.0.0/scripts/setup.php",
	"GET /admin",
	"GET /e107_files/e107.css",	/* Toata dragostea mea pentru diavola */
	"GET /controls/ps3-dbadmin/scripts/setup.php",	/* Toata dragostea mea pentru iEdi */
	"GET /thisdoesnotexistahaha.php",
	"GET //themes/NukeNews/",
	"GET /adxmlrpc.php",
	"GET /cart/install.txt",	/* Toata dragostea mea pentru diavola */
	/* "GET //pma/config/config.inc.php?p=phpinfo();", */
	"GET //pma/",	/* Made by ZmEu @ WhiteHat Team - www.whitehat.ro */
	"GET /scripts/setup.php",	/* ZmEu */
	"GET //sql/",	/* ZmEu */
	"GET //PHPMYADMIN/",	/* ZmEu */
	"GET //dbadmin/config/config.inc.php?p=phpinfo();",
	"GET //horde/util/barcode.php?type=../../../../../../../../../../../../../etc/passwd",
	"GET //web-console/css//dtree.css",
	"GET /webdav/test",
	"GET /webdav/index.html",
	"GET /crossdomain.xml",
	"GET //phpldapadmin/htdocs/",
	"GET //PMA2005/",
	"GET /jmx-console/", /* FHScan Core 1.1 */
	"GET /vicidial/welcome.php",
	"GET /calendar/AUTHORS",
	"GET /appConf.htm",
	"HEAD /manager/status",
	"HEAD /manager/html",
	"GET /appserv/main.php",
	"GET /3rdparty/phpMyAdmin",
	"GET /_phpMyAdmin/scripts/setup.php",
	"GET /sqladmin/scripts/setup.php",
	"GET /sqlmanager/scripts/setup.php",
	"GET /sql/scripts/setup.php",
	"GET /SQL/scripts/setup.php",
	"GET /sqlweb/scripts/setup.php",
	"GET /xampp/phpmyadmin/scripts/setup.php",
	"GET /admin/index.php",
	"GET /phpMyAdmin-2/index.php",
	"GET //phpMyAdmin-2/",
	"GET /translators.html",
	"GET //typo3/phpmyadmin/index.php",
	"GET /xmlrpc.php HTTP/1.1",
	"GET /wp-login.php HTTP/1.1",
	"POST /cgi-bin/php?%2D%64+%61%6C%6C%6F%77%5F%75%72%6C%5F%69%6E%63%6C%75%64%65%3D%6F%6E+%2D%64+%73%61%66%65%5F%6D%6F%64%65%3D%6F%66%66+%2D%64+%73%75%68%6F%73%69%6E%2E%73%69%6D%75%6C%61%74%69%6F%6E%3D%6F",
	"GET /phppath/php",
	"GET //administrator/components/",
	"GET /administrator/index.php",
	"GET /myadmin/scripts/setup.php",
	"GET /HNAP1/",
	"GET /phpTest/zologize/axa.php",
	"GET /cgi-bin/rtpd.cgi?/bin/busybox",
	"GET /muieblackcat",
	"GET /admin/fckeditor/editor/filemanager/browser/default/connectors/test.html",
	"GET /bxbx/bxb/bx.php",
	"GET /xpxp/xpx/xp.php",
	"GET /zbzb/zbz/zb.php",
	"GET /qpqp/qpq/qp.php",
	"GET /juju/juj/ju.php",
	"HEAD /fckeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx",
	"POST http://vlad-tepes.bofh.it/freenode-proxy-checker.txt",
	"GET /tmUnblock.cgi",
	"POST http://check.proxyradar.com",
	"GET /server-status?HTTP_POST=%\"%6346#%#/&#736%\"#423|;&HTTP_CGI_GET=GRESYYK\"K&J\"#L523D2G23H23",	/* apache 0day by @hxmonsegur */
	"GET /MyAdmin/scripts/setup.php",
	"GET /PMA2011/scripts/setup.php",
	"GET /PMA2012/scripts/setup.php",
	"GET /engine/log.txt",
	"GET /stalker_portal/server/adm/users/users-list-json",
	"GET /_asterisk/",
	"GET /login.cgi/cli=aa",
	"masscan/",
	"GET /plugins/weathermap/configs/conn.php?",
	"GET /invoker/readonly",
	"GET /cools.php?id=wget",
	"GET /aastra/aastra.cfg",
	"GET /dana-na/jam/querymanifest.cgi?component=preConfiguration",
	"POST /dns-query",
	"POST /editBlackAndWhiteList",
	"GET /?XDEBUG_SESSION_START=phpstorm",
	"GET ../../",
	"POST /api/jsonws/invoke",
	"GET /?a=fetch&content=<php>die(@md5(HelloThinkCMF))</php>",
	"POST /cgi-bin/mainfunction.cgi",
	"GET /shell?cd+/tmp;rm+-rf+*;wget",
	"/${jndi:ldap://",
	"GET /wp-includes/id3/license.txt/wp/wp-includes/wlwmanifest.xml",
	"GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
	/* OpenWRT hack */
	"GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country",
	"..%252Fetc%252Fpasswd",
	"GET /forum/viewforum.php?f=6&f=..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",
	NULL
};
static	size_t	*http_probelens;
#endif

int	sniff_insert(struct hashtable *h, struct key *k, struct value *v);
struct	value	*sniff_search(struct hashtable *h, struct key *k);
struct	value	*sniff_remove(struct hashtable *h, struct key *k);

DEFINE_HASHTABLE_INSERT(sniff_insert, struct key, struct value)
DEFINE_HASHTABLE_SEARCH(sniff_search, struct key, struct value)
DEFINE_HASHTABLE_REMOVE(sniff_remove, struct key, struct value)

static	int	add_to_whitelist(const char *address);
static	int	add_ip_to_whitelist(const char *address);
static	int	add_to_sacred(const char *program);
static	unsigned	int	iphash(const void *p);
static	int	hasheq(const void *p1, const void *p2);
static	int	scan(struct value *v, union ip_addr saddr, union ip_addr daddr, in_port_t dport);
static	void	kill_route(union ip_addr addr_host_order);
static	void	allow_route(union ip_addr addr_host_order);
static	void	allow_route(union ip_addr addr);
static	void	onexit(void);
#ifdef	CLAMD_CONF
static	int	clamscan(const char *file, char *virusname, const char *socketpath, in_port_t port);
static	int	unix_socket(const char *socket_name);
static	int	ip_socket(const char *hostname, in_port_t portnum);
static	int	recv_data(int s, int tsecs, char *buf, size_t len);
static	void	close_clamd_socket(void);
static	int	send_data(int fd, const void *buff, unsigned int count, const char *socketpath);
#endif
static	void	hashtable_iterate(struct hashtable *h, int scanthem, int foreceunlink);
static	void	destroy(struct hashtable *h, struct key *k, struct value *v);
static	const char	*ipv4tostr(char *s, union ip_addr addr_host_order);
#ifdef	CLAMD_CONF
static	int	getsocknamefromclamdconf(char *buf);
#else
#define	getsocknamefromclamdconf(buf)	(0)
#endif
static	int	iswhitelisted(const union ip_addr *host_order_addr);
#ifdef SITES_ENABLED_DIR
static	void	setup_apache_hosts(void);
#endif

#ifdef SITES_ENABLED_DIR
static	in_port_t	http_port;
#endif
static	struct	hashtable	*hashtable;
static	int	droproutes;
static	int	stopping;
static	int	verbose = 0;
static	int	killprograms;
static	int	timealive = TIMEALIVE;
static	const	char	*tmpdir;
#if(defined(AUTH_LOG) || defined(DOVECOT_LOG))
static	int	max_failures = MAX_FAILURES;
#endif

int
main(int argc, char *const *argv)
{
#ifndef	IPPROTO_TCP
	const struct protoent *protoent;
	int tcp;
#endif
	const char *interface, *pidfile = NULL;
	const struct passwd *passwd;
	struct key *kprealloc = NULL;
	int dont_drop_self = 0;
	int dont_scan_white_listed = 0;
#ifdef SITES_ENABLED_DIR
	int i;
	const char **probe;
#endif
#ifdef	HAVE_LIBPCAP
	bpf_u_int32 deviceaddr, devicemask;
	pcap_t *pcap;
	struct bpf_program fp;
	char errbuf[PCAP_ERRBUF_SIZE];
#else
	int sock;
	short flags;
	const struct sockaddr_in *etheraddr;
	struct ifreq ifreq;
	struct sockaddr_in sin;
#endif
	char buf[BUFSIZ];

	for(;;) {
		int opt_index = 0;
		const char *args = "dhkp:sS:t:T:vVw:W";
		static struct option long_options[] = {
			{
				"drop-routes", 0, NULL, 'd'
			}, {
				"dont-drop-self", 0, NULL, 's'
			}, {
				"help", 0, NULL, 'h'
			}, {
				"kill-programs", 0, NULL, 'k'
			}, {
#if(defined(AUTH_LOG) || defined(DOVECOT_LOG))
				"maximum-failures", 0, NULL, 'm'
			}, {
#endif
				"pidfile", 1, NULL, 'p'
			}, {
				"sacred-program", 1, NULL, 'S'
			}, {
				"time-alive", 1, NULL, 't'
			}, {
				"tmpdir", 1, NULL, 'T'
			}, {
				"verbose", 0, NULL, 'v'
			}, {
				"version", 0, NULL, 'V'
			}, {
				"white-list", 1, NULL, 'w'
			}, {
				"dont-scan-white-listed", 0, NULL, 'W'
			}, {
				NULL, 0, NULL, '\0'
			}
		};

		int ret = getopt_long(argc, argv, args, long_options, &opt_index);

		if(ret == -1)
			break;
		else if(ret == 0)
			continue;

		switch(ret) {
			case 'd':
				droproutes++;
				break;
			case 'p':
				pidfile = optarg;
				break;
			case 'k':
				killprograms++;
				break;
#if(defined(AUTH_LOG) || defined(DOVECOT_LOG))
			case 'm':
				max_failures = atoi(optarg);
				if(max_failures < 0) {
					fprintf(stderr, "%s: -m argument can't be negative\n",
						argv[0]);
					return 1;
				}
#endif
				break;
			case 's':
				/*
				 * Useful when using sniff2ban to monitor
				 * outgoing emails where we want to see what's
				 * going on, but don't want to block all traffic
				 */
				dont_drop_self++;
				break;
			case 'T':
				tmpdir = optarg;
				break;
			case 't':
				timealive = atoi(optarg);
				if(timealive < 0) {
					fprintf(stderr, "%s: -t argument can't be negative\n",
						argv[0]);
					return 1;
				}
				break;
			case 'v':
				verbose++;
				break;
			case 'V':
				puts(PACKAGE_STRING);
				return 0;
			case 'w':
				if(!add_to_whitelist(optarg)) {
					fprintf(stderr, "%s: Failed to whitelist %s\n",
						argv[0], optarg);
					return 1;
				}
				break;
			case 'W':
				dont_scan_white_listed++;
				break;
			case 'S':
				if(!add_to_sacred(optarg)) {
					fprintf(stderr, "%s: Failed to sacred list %s\n",
						argv[0], optarg);
					return 1;
				}
				break;
			default:
				fprintf(stderr, "Usage: %s [-d] [-k] [-s] [-T dir] [-t secs] [-v] [-w IP address] [ -V ] [ -W ] [-p pidfile] [-S sacred_program ] [ socket ] [ interface ]\n", argv[0]);
				return 1;
		}
	}

	/*
	 * Sanity checks
	 */
	if(!droproutes) {
		if(whitelist) {
			fputs("You have specified addresses to whitelist, but not to drop routes\n", stderr);
			return 1;
		}
		if(dont_drop_self) {
			fputs("You have specified the -s flag, but not the -d flag\n", stderr);
			return 1;
		}
	}
	if(sacredlist_tail && !killprograms) {
		fputs("You have specified a sacred program list, but not requested to kill programs\n", stderr);
		return 1;
	}

#ifdef	HAVE_LIBPCAP
	if(optind == argc) {
		interface = pcap_lookupdev(errbuf);
		if(verbose && interface)
			printf("%s: Monitoring %s for malware\n", argv[0], interface);
#ifdef	CLAMD_CONF
		if(!getsocknamefromclamdconf(buf)) {
			/*
			 * No means to talk to clamd or interface given and
			 * there is no clamd.conf to work it out, therefore
			 * the socket must be given
			 */
			fputs("Couldn't determine how to talk to clamd\n", stderr);
			fprintf(stderr, "Usage: %s [-d] [-k] [-s] [-t secs] [-v] [-w IP address] [ -W ] [-S sacred_program ] socket [ interface ]\n", argv[0]);
			return 1;
		}
		if(verbose >= 2)
			printf("%s: Using %s as the ClamAV socket\n", argv[0], buf);
		sockname = buf;
#endif
	} else if(optind == (argc - 1)) {
		interface = pcap_lookupdev(errbuf);
		if(verbose && interface)
			printf("%s: Monitoring %s for malware\n", argv[0], interface);
		sockname = argv[optind++];
	} else {
		if(optind != (argc - 2)) {
			if(!getsocknamefromclamdconf(buf)) {
				/*
				 * No means to talk to clamd or interface given
				 * and there is no clamd.conf to work it out,
				 * therefore the socket must be given
				 */
				fputs("Couldn't determine how to talk to clamd\n", stderr);
				fprintf(stderr, "Usage: %s [-d] [-k] [-s] [-t secs] [-v] [-w IP address] [ -W ] [-S sacred_program ] socket [ interface ]\n", argv[0]);
				return 1;
			}
			if(verbose >= 2)
				printf("%s: Using %s as the ClamAV socket\n", argv[0], buf);
			sockname = buf;
		} else
			sockname = argv[optind++];
		interface = NULL;
	}
#elif	defined(CLAMD_CONF)
	if(optind != (argc - 2)) {
		if(!getsocknamefromclamdconf(buf)) {
			/* No means to talk to clamd or interface given */
			fputs("Couldn't determine how to talk to clamd\n", stderr);
			fprintf(stderr, "Usage: %s [-d] [-k] [-s] [-t secs] [-v] [-w IP address] [ -W ] [-S sacred_program ] socket [ interface ]\n", argv[0]);
			return 1;
		}
		if(verbose >= 2)
			printf("Using %s as the ClamAV socket\n", buf);
		sockname = buf;
	} else
		sockname = argv[optind++];

	if(sockname && (sockname[0] != '/')) {
		char *ptr = strchr(sockname, ':');

		if(ptr == NULL) {
			fprintf(stderr, "%s: No port number given to talk to clamd in %s\n",
				argv[0], sockname);
			return 1;
		}
		*ptr++ = '\0';
		if(!isdigit(*ptr)) {
			fprintf(stderr, "%s: Invalid port number given '%s'\n",
				argv[0], ptr);
			return 1;
		}
		sockport = atoi(ptr);
		if(sockport <= 0) {
			fprintf(stderr, "%s: Invalid port number given '%s'\n",
				argv[0], ptr);
			return 1;
		}
	}
	/* TODO: validate sockname by sending PING to clamd */
#endif

#ifdef	HAVE_LIBPCAP
	if(argv[optind])
		interface = argv[optind];
	if(interface == NULL) {
		fputs("Couldn't determine a default device\n", stderr);
		fprintf(stderr, "Usage: %s [-d] [-k] [-s] [-t secs] [-v] [-w IP address] [ -W ] [-S sacred_program ] [ socket ] interface\n", argv[0]);
		return 1;
	}
	/* Open the device in promiscuous mode */
	pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if(pcap == NULL) {
		fprintf(stderr, "%s: Couldn't open device %s: %s\n",
			argv[0], interface, errbuf);
		return 2;
	}
#else
	interface = argv[optind];

	if(interface == NULL) {
		fputs("No Interface given\n", stderr);
		fprintf(stderr, "Usage: %s [-d] [-k] [-s] [-t secs] [-v] [-w IP address] [ -W ] [-S sacred_program ] [ socket ] interface\n", argv[0]);
		return 1;
	}

	/*
	 * Don't use ETH_P_IP so that we can catch FTP transfers
	 */
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket");
		return errno;
	}

	strncpy(ifreq.ifr_name, interface, IFNAMSIZ);
	ioctl(sock, SIOCGIFFLAGS, &ifreq);
	flags = ifreq.ifr_flags;
	if(!(flags&IFF_PROMISC)) {
		ifreq.ifr_flags |= IFF_PROMISC;
		if(ioctl(sock, SIOCSIFFLAGS, &ifreq) < 0) {
			perror("ioctl");
			return errno;
		}
	}
#endif
	if(dont_scan_white_listed && (!dont_drop_self) && (whitelist_tail == NULL))
		puts("Warning: -W given, but not -w which is probably not what you wanted");

#ifdef SITES_ENABLED_DIR
	if(verbose)
		printf("%s: Will scan HTTP messages for sites listed in %s\n",
			argv[0], SITES_ENABLED_DIR);
	setup_apache_hosts();
#else
	if(verbose >= 2)
		printf("%s: Will not scan HTTP messages\n", argv[0]);
#endif

#ifdef	AUTH_LOG
	if(verbose)
		printf("%s: Will scan SSH failures listed in %s\n",
			argv[0], AUTH_LOG);
#endif

#ifdef	DOVECOT_LOG
	if(verbose)
		printf("%s: Will scan Dovecot failures listed in %s\n",
			argv[0], DOVECOT_LOG);
#endif

	passwd = getpwnam("clamav");
	if(!droproutes) {
		if(passwd) {
			if(setgid(passwd->pw_gid) < 0)
				perror("setgid");
			if(setuid(passwd->pw_uid) < 0)
				perror("setuid");
		} else
			fputs("No ClamAV user - running as root is dangerous\n", stderr);
	}
	endpwent();

	umask(077);
#ifdef	HAVE_LIBPCAP
	if(pcap_lookupnet(interface, &deviceaddr, &devicemask, errbuf) == -1) {
		fprintf(stderr, "%s: Couldn't get address of device %s\n",
			argv[0], interface);
		return 3;
	}
	pcap_set_datalink(pcap, DLT_EN10MB);
#else
	ioctl(sock, SIOCGIFADDR, &ifreq);

	etheraddr = (const struct sockaddr_in *)&ifreq.ifr_addr;
	memcpy(&sin, etheraddr, sizeof(struct sockaddr_in));

	if(bind(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) < 0)
		perror(inet_ntoa(sin.sin_addr));
#endif

	if(dont_drop_self) {
		if(whitelist == NULL)
			whitelist_tail = whitelist = malloc(sizeof(struct whitelist));
		else {
			whitelist_tail->next = malloc(sizeof(struct whitelist));
			whitelist_tail = whitelist_tail->next;
		}

#ifdef	HAVE_LIBPCAP
		whitelist_tail->addr.i = deviceaddr;
		pcap_setdirection(pcap, PCAP_D_IN);
		if(verbose >= 2) {
			struct in_addr addr;
			union ip_addr mask;

			addr.s_addr = deviceaddr;
			mask.i = devicemask;
			printf("%s: Not checking self (%s/%d.%d.%d.%d) for malware\n",
				argv[0], inet_ntoa(addr),
				mask.c[0], mask.c[1], mask.c[2], mask.c[3]);
		}
		whitelist_tail->mask = ntohl(devicemask);
#else
		whitelist_tail->addr.i = etheraddr->sin_addr.s_addr;
		whitelist_tail->mask = 0xFFFFFFFF;
#endif
		whitelist_tail->next = NULL;
	}

#ifndef	IPPROTO_TCP
	/* If IPPROTO_TCP isn't defined try /etc/protocols */
	protoent = getprotoent("tcp");
	if(protoent == NULL) {
		fprintf(stderr, "%s: Can't work out the TCP protocol number\n",
			argv[0]);
#ifdef	HAVE_LIBPCAP
		pcap_close(pcap);
#endif
		return 3;
	}
	tcp = protoent->p_proto;
	endprotoent();
#endif

#ifdef SITES_ENABLED_DIR
	i = 0;
	for(probe = http_probes; *probe; probe++)
		i++;

	http_probelens = malloc(i * sizeof(size_t));
	if(http_probelens == NULL) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
#ifdef	HAVE_LIBPCAP
		pcap_close(pcap);
#endif
		return 4;
	}
	i = 0;
	for(probe = http_probes; *probe; probe++)
		http_probelens[i++] = strlen(*probe);
#endif

#ifdef	HAVE_LIBPCAP
	if(pcap_compile(pcap, &fp, "tcp", 0, deviceaddr) >= 0) {
		if(pcap_setfilter(pcap, &fp) < 0)
			fprintf(stderr, "%s: Error setting filter \"tcp\"\n",
				argv[0]);
	} else
		fprintf(stderr, "%s: Error with pcap_compile \"tcp\"\n",
			argv[0]);
#endif

	if(!verbose)
		switch(fork()) {
			case -1:
				perror("fork");
				return errno;
			case 0:
				/*close(0);
				close(1);
				close(2);
				open("/dev/null", O_RDONLY);
				open("/dev/null", O_WRONLY);
				dup(1);*/
				break;
			default:
				return 0;
		}

	if(pidfile) {
		/*
		 * Add a pidfile, useful for monit(1) and puppet(1)
		 * to restart if sniff2ban dies
		 */
		FILE *p = fopen(pidfile, "w");

		if(p == NULL) {
			perror(pidfile);
			return errno;
		}
		fprintf(p, "%d\n", getpid());
		fclose(p);
	}

	if(tmpdir == NULL) {
		if(getenv("TMPDIR"))
			tmpdir = getenv("TMPDIR");
		else if(P_tmpdir)
			tmpdir = P_tmpdir;
		else
			tmpdir = "/tmp";
	}

	openlog(argv[0], LOG_CONS|LOG_PID, LOG_DAEMON);

	hashtable = create_hashtable(200, iphash, hasheq);

#ifdef	HAVE_SIG_T
	signal(SIGTERM, (sig_t)onexit);
	signal(SIGINT, (sig_t)onexit);
#elif	defined(HAVE_SIGHANDLER_T)
	signal(SIGTERM, (__sighandler_t)onexit);
	signal(SIGINT, (__sighandler_t)onexit);
#else
	signal(SIGTERM, onexit);
	signal(SIGINT, onexit);
#endif

	atexit(onexit);

#ifdef	SIGPIPE
	signal(SIGPIPE, SIG_IGN);
#endif

	while(!stopping) {
		ssize_t nbytes, payloadlength;
		uint16_t sport, dport;
		const struct ether_header *ethhdr;
#ifdef HAVE_STRUCT_IPHDR
		const struct iphdr *iphdr;
#else
		const struct ip *iphdr;
#endif
		const struct tcphdr *tcphdr;
		const unsigned char *ptr;
		struct key *k;
		struct value *v;
		union ip_addr source_addr, dest_addr;
#ifdef	HAVE_LIBPCAP
		const u_char *buffer;
		struct pcap_pkthdr header;
#else
		unsigned char buffer[MAXBYTES];
#endif

#ifdef	HAVE_LIBPCAP
		buffer = pcap_next(pcap, &header);
		if(buffer == NULL) {
			/*fprintf(stderr, "%s: Error reading data from %s\n",
				argv[0], interface);
			hashtable_iterate(hashtable, 0, 1);
			pcap_close(pcap);
			return 1;*/
			hashtable_iterate(hashtable, 1, 0);
			continue;
		}
		nbytes = header.len;
#else
		nbytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
		if(nbytes < 0) {
			perror("recvfrom");
			hashtable_iterate(hashtable, 0, 1);
			close(sock);
			return errno;
		}
#endif
		if(nbytes < (ssize_t)sizeof(struct ether_header)) {
			puts("too small");
			continue;
		}
		ethhdr = (const struct ether_header *)buffer;

#ifdef	ETHERTYPE_IP
		if(ntohs(ethhdr->ether_type) != ETHERTYPE_IP) {
			/*printf("ether proto %d\n", ntohs(ethhdr->ether_type));*/
			continue;
		}
#else
		if(ntohs(ethhdr->ether_type) != ETH_P_IP) {
			/*printf("ether proto %d\n", ntohs(ethhdr->ether_type));*/
			continue;
		}
#endif

#ifdef HAVE_STRUCT_IPHDR
		iphdr = (const struct iphdr *)&buffer[sizeof(struct ether_header)];
#ifdef	IPPROTO_TCP
		if((int)iphdr->protocol != IPPROTO_TCP) {
			/*printf("IP proto %d\n", (int)iphdr->protocol);*/
			hashtable_iterate(hashtable, 1, 0);
			continue;
		}
#else
		if((int)iphdr->protocol != tcp) {
			/*printf("IP proto %d\n", (int)iphdr->protocol);*/
			hashtable_iterate(hashtable, 1, 0);
			continue;
		}
#endif
#else
		iphdr = (const struct ip *)&buffer[sizeof(struct ether_header)];

		if((int)iphdr->ip_p != IPPROTO_TCP) {
			/*printf("IP proto %d\n", (int)iphdr->ip_p);*/
			hashtable_iterate(hashtable, 1, 0);
			continue;
		}
#endif

		tcphdr = (const struct tcphdr *)&buffer[sizeof(struct ether_header) + sizeof(struct ip)];

#if	0
		if((iphdr->saddr == htonl(INADDR_LOOPBACK)) || (iphdr->daddr == htonl(INADDR_LOOPBACK))) {
			/*
			 * TODO: remove this code once the bind() code has been
			 *	written
			 */
			puts("loop");
			hashtable_iterate(hashtable, 1, 0);
			continue;
		}
#endif

#ifdef	HAVE_LIBPCAP
#if	0
		if(((iphdr->saddr&devicemask) != deviceaddr) && ((iphdr->daddr&devicemask) != deviceaddr)) {
			/*struct in_addr addr;

			memcpy(&addr, &iphdr->saddr, sizeof(struct in_addr));
			printf("filter out saddr = %s ", inet_ntoa(addr));
			memcpy(&addr, &iphdr->saddr, sizeof(struct in_addr));
			printf("daddr = %s ", inet_ntoa(addr));
			memcpy(&addr, &deviceaddr, sizeof(struct in_addr));
			printf("deviceaddr = %s\n", inet_ntoa(addr));*/
			hashtable_iterate(hashtable, 1, 0);
			continue;
		}
#endif
#else
		if((iphdr->saddr != etheraddr->sin_addr.s_addr) && (iphdr->daddr != etheraddr->sin_addr.s_addr)) {
			/* The above bind fails, so let's filter here */
			/*puts("filter out");*/
			hashtable_iterate(hashtable, 1, 0);
			continue;
		}
#endif

#ifdef HAVE_STRUCT_IPHDR
		if(iphdr->daddr == 0) {
			/* FIXME: What are these? */
			puts("Destination IP is 0");
			continue;
		}

		source_addr.i = iphdr->saddr;
		sport = ntohs(tcphdr->source);
		dest_addr.i = iphdr->daddr;
		dport = ntohs(tcphdr->dest);
#else
		memcpy(&source_addr.i, &iphdr->ip_src, sizeof(source_addr.i));
		sport = ntohs(tcphdr->th_sport);
		memcpy(&dest_addr.i, &iphdr->ip_dst, sizeof(source_addr.i));
		dport = ntohs(tcphdr->th_dport);
#endif

		if(verbose >= 3) {
			struct in_addr in_addr;

			in_addr.s_addr = source_addr.i;
			printf("%s:%d->", inet_ntoa(in_addr), sport);

			in_addr.s_addr = dest_addr.i;
			printf("%s:%d", inet_ntoa(in_addr), dport);
#ifdef HAVE_STRUCT_IPHDR
			printf(" seq %u", ntohl(tcphdr->seq));
			if(tcphdr->fin)
				fputs(" FIN", stdout);
			if(tcphdr->syn)
				fputs(" SYN", stdout);
#else
			printf(" seq %u", ntohl(tcphdr->th_seq));
			if(tcphdr->th_flags&TH_FIN)
				fputs(" FIN", stdout);
			if(tcphdr->th_flags&TH_SYN)
				fputs(" SYN", stdout);
#endif
		}

#ifdef HAVE_STRUCT_IPHDR
		ptr = &buffer[sizeof(struct ether_header) + sizeof(struct iphdr) + (tcphdr->doff * sizeof(uint32_t))];
		payloadlength = nbytes - sizeof(struct ether_header) - sizeof(struct iphdr) - (tcphdr->doff * sizeof(uint32_t));
#else
		ptr = &buffer[sizeof(struct ether_header) + sizeof(struct ip) + (tcphdr->th_off * sizeof(uint32_t))];
		payloadlength = nbytes - sizeof(struct ether_header) - sizeof(struct ip) - (tcphdr->th_off * sizeof(uint32_t));
#endif

		if(verbose >= 3)
			printf(" %ld bytes\n", (long)payloadlength);

		if(payloadlength == 0)
			continue;

		if(kprealloc == NULL)
			kprealloc = malloc(sizeof(struct key));
		k = kprealloc;

#ifdef HAVE_STRUCT_IPHDR
		k->saddr.i = iphdr->saddr;
		k->daddr.i = iphdr->daddr;
#else
		memcpy(&k->saddr.i, &iphdr->ip_src, sizeof(k->saddr.i));
		memcpy(&k->daddr.i, &iphdr->ip_dst, sizeof(k->daddr.i));
#endif
		k->sport = sport;
		k->dport = dport;

		v = sniff_search(hashtable, k);
		if(v) {
			off_t nbytesread = v->nbytes;
#ifdef	TH_SYN
			if(tcphdr->th_flags&TH_SYN) {
#else
			if(tcphdr->syn) {
#endif
				/*
				 * Remote end is trying to create another
				 * connection. Start a new dataset. There's
				 * no need to deny the connection if the remote
				 * end is infected, since the firewall we put
				 * up will stop this (if -d is given)
				 */
				destroy(hashtable, k, v);
				v = NULL;
			}
			if(nbytesread > MAXSCANSIZE)
				continue;
			v = NULL;
		}
		if(v == NULL) {
			int scan;
			struct in_addr in_addr;
			char filename[128];

			if(dont_scan_white_listed)
				if(iswhitelisted(&source_addr)) {
					if(verbose >= 3) {
						char addr[128];

						(void)ipv4tostr(addr, source_addr);
						fprintf(stderr, "Not scanning whitelisted address %s\n",
							addr);
					}
					continue;
				}

			scan = 0;
			if(dport == 25)
				scan = 1;
#ifdef SITES_ENABLED_DIR
			/* FIXME: http_port == 0 until scan() is called */
			if((dport == http_port) || (http_port == 0))
				scan = 1;
#endif
#ifdef	AUTH_LOG
			if(dport == 22)
				scan = 1;
#endif
#ifdef	DOVECOT_LOG
			if((dport == 110) || (dport == 993))
				scan = 1;
#endif
			if(scan == 0) {
				if(verbose >= 3)
					fprintf(stderr, "Not scanning to destination port %d\n", dport);
				continue;
			}

			/* TODO: use TMPDIR */
			in_addr.s_addr = source_addr.i;

			snprintf(filename, sizeof(filename), "%s/%s:%d-%d.%d.%d.%d:%d",
				 tmpdir, inet_ntoa(in_addr), sport,
				 dest_addr.c[0], dest_addr.c[1], dest_addr.c[2],
				 dest_addr.c[3], dport);

			v = calloc(1, sizeof(struct value));
			v->fp = fopen(filename, "wx");
			if(v->fp == NULL) {
				if(errno == EEXIST) {
					/*
					 * Try once more, presumably we've just
					 * received a new connection from a
					 * client that's just closed a previous
					 * connection and we haven't yet tidied
					 * up
					 */
					sleep(1);
					v->fp = fopen(filename, "wx");
				}
				if(v->fp == NULL) {
					if(errno != EEXIST) {
						perror(filename);
					}
					free(v);

					continue;
				}
			}
			if(droproutes && passwd)
				/*
				 * Running as root, ensure clamd can read the file
				 */
#ifdef	HAVE_FCHOWN
				if(fchown(fileno(v->fp), passwd->pw_uid, passwd->pw_gid) < 0)
					perror(filename);
#else
				if(chown(filename, passwd->pw_uid, passwd->pw_gid) < 0)
					perror(filename);
#endif
			v->filename = strdup(filename);

			sniff_insert(hashtable, k, v);
			kprealloc = NULL;
		}
		if(v->fp) {
			v->nbytes += fwrite(ptr, sizeof(unsigned char), payloadlength, v->fp);
			time(&v->lastwritten);

#ifndef SITES_ENABLED_DIR
			if(v->lastscanned == (time_t)0)
				/*
				 * Lie - don't scan the first packet
				 * ClamAV is a file scanner not a network
				 * scanner, so there's no point in scanning
				 * a packet that's half way through a file,
				 * which will often be the case at start
				 * up of the program. OK, I understand
				 * that we will still scan on second
				 * and subsequent bits, but this does
				 * help a little
				 */
				v->lastscanned = time((time_t *)0);
			else {
#else
			{
#endif
				union ip_addr s, d;

#ifdef	TH_FIN
#ifdef HAVE_STRUCT_IPHDR
				memcpy(&s.i, &iphdr->saddr, sizeof(s.i));
				memcpy(&d.i, &iphdr->daddr, sizeof(d.i));
#else
				memcpy(&s.i, &iphdr->ip_src, sizeof(s.i));
				memcpy(&d.i, &iphdr->ip_dst, sizeof(d.i));
#endif
				if(tcphdr->th_flags&TH_FIN)
					v->forcescan = 1;
#else
				s.i = iphdr->saddr;
				d.i = iphdr->daddr;
				if(tcphdr->fin)
					v->forcescan = 1;
#endif

				scan(v, s, d, dport);
#ifdef	TH_FIN
				if(tcphdr->th_flags&TH_FIN) {
#else
				if(tcphdr->fin) {
#endif
					if(k && !droproutes)
						destroy(hashtable, k, v);
					else {
						fclose(v->fp);
						if(unlink(v->filename) < 0)
							perror(v->filename);
						free(v->filename);
						v->filename = NULL;
						v->fp = NULL;
					}
				}
			}
		}

		hashtable_iterate(hashtable, 1, 0);

#if	0
		if(sport == 3128) {
			int i;
			const unsigned char *payload = ptr;

			for(i = 0; i < payloadlength; i++)
				putchar(*payload++);
			putchar('\n');
		}
#endif
	}

	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);

#ifdef	HAVE_LIBPCAP
	pcap_close(pcap);
#else
	strncpy(ifreq.ifr_name, interface, IFNAMSIZ);
	ioctl(sock, SIOCGIFFLAGS, &ifreq);
	ifreq.ifr_flags = flags;
	if(ioctl(sock, SIOCSIFFLAGS, &ifreq) < 0)
		perror("ioctl");
#endif

	if(hashtable) {
		hashtable_iterate(hashtable, 0, 1);

		hashtable_destroy(hashtable, 1);

		hashtable = (struct hashtable *)NULL;
	}

	closelog();

	if(kprealloc)
		free(kprealloc);

	if(pidfile)
		if(unlink(pidfile) < 0)
			perror(pidfile);

#ifdef	HAVE_LIBPCAP
	return 0;
#else
	return close(sock);
#endif
}

static int
add_to_whitelist(const char *address)
{
	struct in_addr in_addr;
	u_char *p, *end;
	int len, i;
	const HEADER *hp;
	union {
		HEADER h;
		u_char u[PACKETSZ];
	} q;
	char buf[BUFSIZ];

	if(inet_pton(AF_INET, address, &in_addr) > 0)
		return add_ip_to_whitelist(address);
	if(strchr(address, '/'))	/* IP range */
		return add_ip_to_whitelist(address);

	/* Resolve the hostname */

	len = res_query(address, C_IN, T_A, (u_char *)&q, sizeof(q));

	if(len < 0) {
		fprintf(stderr, "Unknown host %s\n", address);
		return 0;
	}

	hp = &(q.h);
	p = q.u + HFIXEDSZ;
	end = q.u + len;

	for(i = ntohs(hp->qdcount); i--; p += len + QFIXEDSZ)
		if((len = dn_skipname(p, end)) < 0) {
			fprintf(stderr, "Unknown host %s\n", address);
			return 0;
		}

	i = ntohs(hp->ancount);

	if(i <= 0) {
		fprintf(stderr, "Unknown host %s\n", address);
		return 0;
	}

	while((--i >= 0) && (p < end)) {
		u_short type;
		u_long ttl;
		const char *ip;
		struct in_addr addr;

		if((len = dn_expand(q.u, end, p, buf, sizeof(buf) - 1)) < 0) {
			fprintf(stderr, "Unknown host %s\n", address);
			return 0;
		}
		p += len;
		GETSHORT(type, p);
		p += INT16SZ;
		GETLONG(ttl, p);	/* unused */
		GETSHORT(len, p);
		if(type != T_A) {
			p += len;
			continue;
		}
		memcpy(&addr, p, sizeof(struct in_addr));
		p += 4; /* Should check len == 4 */
		ip = inet_ntoa(addr);
		if(ip)
			if(!add_ip_to_whitelist(ip))
				return 0;
	}
	return 1;
}

static int
add_ip_to_whitelist(const char *address)
{
	char *p;
	int i;
	struct in_addr in_addr;
	char copy[20];	/* IPv4 only + netmasks */

	if(strlen(address) >= sizeof(copy)) {
		fputs("Whitelisting only works on IP addresses\n", stderr);
		return 0;
	}
	strcpy(copy, address);

	p = strchr(copy, '/');	/* allow network masks */
	if(p)
		*p++ = '\0';

	if(inet_pton(AF_INET, copy, &in_addr) <= 0) {
		fputs("Whitelisting only works on IP addresses\n", stderr);
		return 0;
	}
	if(whitelist == NULL)
		whitelist_tail = whitelist = malloc(sizeof(struct whitelist));
	else {
		whitelist_tail->next = malloc(sizeof(struct whitelist));
		whitelist_tail = whitelist_tail->next;
	}
	if(whitelist_tail == NULL)
		return 0;

	whitelist_tail->addr.i = in_addr.s_addr;

	i = (p && *p) ? atoi(p) : 32;
	whitelist_tail->mask = (uint32_t)(0xFFFFFFFF << (32 - i));

	whitelist_tail->next = NULL;

	return 1;
}

static int
add_to_sacred(const char *program)
{
	if(program == NULL)
		return 0;

	if(sacredlist == NULL)
		sacredlist_tail = sacredlist = malloc(sizeof(struct sacredlist));
	else {
		sacredlist_tail->next = malloc(sizeof(struct sacredlist));
		sacredlist_tail = sacredlist_tail->next;
	}
	if(sacredlist_tail == NULL)
		return 0;

	sacredlist_tail->program = strdup(program);	/* Never freed */
	sacredlist_tail->next = NULL;

	return 1;
}

static unsigned int
iphash(const void *p)
{
	unsigned int hash = 5381;
	const unsigned char *q1 = (const unsigned char *)p, *q2 = (const unsigned char *)p;

	while((q2 - q1) < (int)(sizeof(struct key)))
		hash = ((hash << 5) + hash) ^ *q2++; /* hash * 33 + ^ */

	return hash;
}

static int
hasheq(const void *p1, const void *p2)
{
	if(p1 == p2)
		return 1;
	return memcmp(p1, p2, sizeof(struct key)) == 0;
}

/*
 * Returns 0 for clean, 1 for infected
 * Addresses are in host order
 * TODO: Pass key instead of saddr, daddr, dport
 */
static int
scan(struct value *v, union ip_addr saddr, union ip_addr daddr, in_port_t dport)
{
	time_t now;
	const char *malware_type;
	char virusname[255];

	if(v->nbytes < MINSCANSIZE)
		return 0;

	if(v->nbytes >= MAXSCANSIZE)
		return 0;

	if(v->infected)	/* Don't scan if we know it's infected */
		return 0;	/* Pretend it's clean - saves repeat messages */

	now = time((time_t *)0);

	if(!v->forcescan)
		if((now - v->lastscanned) < MIN_SCAN_OFTEN_SECS)
			return 0;

	v->forcescan = 0;

	fflush(v->fp);

	/*printf("scan %s\n", v->filename);*/

	v->lastscanned = now;
	malware_type = "VIRUS";

#ifdef SITES_ENABLED_DIR
	/*
	 * Proof of concept - let's see where this leads us
	 */
	if(http_port == 0) {
		const struct servent *servent = getservbyname("http", "tcp");

		if(servent == NULL) {
			fputs("Can't find http in /etc/services\n", stderr);
			return 0;
		}
		endservent();
		http_port = ntohs(servent->s_port);
	}
	if(dport == http_port) {
		FILE *fin = fopen(v->filename, "r");
		char *contents;
		off_t nbytes;
		int i, ret;
		const char **probe;
		struct stat statb;

		if(fin == NULL) {
			perror(v->filename);
			return 0;
		}
		fstat(fileno(fin), &statb);
		nbytes = statb.st_size;
		if(nbytes == 0) {
			fclose(fin);
			return 0;
		}
		contents = malloc(nbytes + 1);
		if(contents == NULL) {
			fclose(fin);
			fprintf(stderr, "Can't allocate %lu bytes\n", (unsigned long)nbytes);
			return 0;
		}
		if(fread(contents, sizeof(char), (size_t)nbytes, fin) != (size_t)nbytes) {
			perror(v->filename);
			contents[0] = '\0';
		}
		fclose(fin);
		virusname[0] = contents[nbytes] = '\0';
#ifdef	HAVE_MEMMEM
		ret = i = 0;
		for(probe = http_probes; *probe; probe++) {
			/* TODO: This should be case independent */
			ret = (memmem(contents, nbytes, *probe, http_probelens[i++]) != NULL);
			if(ret) {
				strcpy(virusname, *probe);
				break;
			}
		}

		if(!ret) {
			const char *p = memmem(contents, nbytes, "GET http://", 11);

			if(p != NULL) {
				const struct apachehosts *a;

				ret = 1;
				p = &p[11];

				/*
				 * Look through our vhosts, if it's one
				 * of them it's OK
				 */
				for(a = apachehosts; a; a = a->next)
					if(strncmp(p, a->name, strlen(a->name)) == 0) {
						ret = 0;
						break;
					}
				/*
				 * Not one of our vhosts, but it could be
				 * direct to our IP address, which would also
				 * be OK
				 */
				if(ret) {
					char d[MAXHOSTNAMELEN + 1];

					ipv4tostr(d, daddr);

					if(strncmp(p, d, strlen(d)) == 0)
						ret = 0;
				}
				/*
				 * If ret == 1 then someone is probing us,
				 * most likely to see if we are some sort
				 * of open relay
				 */
				if(ret == 1) {
					strcpy(virusname, "Probing for open http server");
					malware_type = "HTTP PROBE";
				}
			}
		}

		if(!ret)
			/* Probing for open email relay? */
			if((memmem(contents, nbytes, "CONNECT ", 8) != NULL) /*&& (strstr(contents, ":25 HTTP/") != NULL)*/) {
				ret = 1;
				strcpy(virusname, "CONNECT probe");
				malware_type = "CONNECT PROBE";
			}
		if(!ret)
			if((memmem(contents, nbytes, "bash", 4) != NULL) &&
			   (memmem(contents, nbytes, "};", 2) != NULL)) {
				ret = 1;
				strcpy(virusname, "shellshock");
				malware_type = "SHELLSHOCK PROBE";
			}
		if(!ret)
			if(memmem(contents, nbytes, "bash -c 'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' || echo", 106) != NULL) {
				ret = 1;
				strcpy(virusname, "shellshock");
				malware_type = "SHELLSHOCK PROBE";
			}
#else	/*!HAVE_MEMMEM*/
		/*
		 * FIXME: Handle keep-alives when there could be more than one
		 *	GET per connection
		 */
		ret = i = 0;
		for(probe = http_probes; *probe; probe++) {
#ifdef HAVE_STRNCASECMP
			ret = (strncasecmp(contents, *probe, http_probelens[i++]) != NULL);
#else
			ret = (strncmp(contents, *probe, http_probelens[i++]) != NULL);
#endif
			if(ret) {
				strcpy(virusname, *probe);
				break;
			}
		}

		if(!ret)
			if((strncmp(contents, "GET http://", 11) == 0) ||
			   (strncmp(contents, "POST http://", 12) == 0) ||
			   (strncmp(contents, "HEAD http://", 12) == 0)) {
				const char *p = &contents[11];
				const struct apachehosts *a;

				ret = 1;

				/*
				 * Look through our vhosts, if it's one
				 * of them it's OK
				 */
				for(a = apachehosts; a; a = a->next)
					if(strncmp(p, a->name, strlen(a->name)) == 0) {
						ret = 0;
						break;
					}
				/*
				 * Not one of our vhosts, but it could be
				 * direct to our IP address, which would also
				 * be OK
				 */
				if(ret) {
					char d[MAXHOSTNAMELEN + 1];

					ipv4tostr(d, daddr);

					if(strncmp(p, d, strlen(d)) == 0)
						ret = 0;
				}
				/*
				 * If ret == 1 then someone is probing us,
				 * most likely to see if we are some sort
				 * of open relay
				 */
				if(ret == 1) {
					strcpy(virusname, "Probing for open http server");
					malware_type = "HTTP PROBE";
				}
			}

		if(!ret)
			/* Probing for open email relay? */
			if((strncmp(contents, "CONNECT ", 8) == 0) /*&& (strstr(contents, ":25 HTTP/") != NULL)*/) {
				ret = 1;
				strcpy(virusname, "CONNECT probe");
				malware_type = "CONNECT PROBE";
			}
		if(!ret)
			if((strstr(contents, "bash") != NULL) &&
			   (strstr(contents, "};") != NULL)) {
				ret = 1;
				strcpy(virusname, "shellshock");
				malware_type = "SHELLSHOCK PROBE";
			}
		if(!ret)
			if(strstr(contents, "bash -c 'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' || echo") != NULL) {
				ret = 1;
				strcpy(virusname, "shellshock");
				malware_type = "SHELLSHOCK PROBE";
			}
#endif	/*HAVE_MEMMEM*/

		free(contents);
		if(ret) {
			v->infected = 1;
			if(virusname[0] == '\0')
				strcpy(virusname, "Trying to hack in");
		}
	}
#endif

#ifdef	AUTH_LOG	/* FIXME: Should be ifdef ENABLE_SSH_SCANNING */
	/*
	 * POC:
	 * Don't enable this, I know how horrible the implementation is at
	 * the moment.  I'm toying with doing this sort of thing. I know
	 * about breakinguard and fail2ban
	 *
	 * TODO: Only drop if 5 failed attempts to login
	 */
#ifdef SITES_ENABLED_DIR
	else if(dport == 22) {
#else
	if(dport == 22) {
#endif
		FILE *p;
		int failures = 0;
		char s[100], c[200];

		/*printf("SSH from %s\n", ipv4tostr(s, saddr));*/
		sprintf(c, "tail -20 %s|fgrep %s|fgrep sshd|grep -v Accepted",
			AUTH_LOG, ipv4tostr(s, saddr));

		p = popen(c, "r");
		if(p != NULL) {
			char l[222];

			while(fgets(l, sizeof(l), p) != NULL)
				if(strstr(l, "Failed password for ")) {
					failures++;
					/*fputs(l, stdout);*/
					/*
					 * Can't break, gets Broken Pipe from grep
					 */
					/*break;*/
				}
			pclose(p);
			if(failures >= max_failures) {
				strcpy(virusname, "SSH attack");
				malware_type = "SSH attack";
				v->infected = 1;
			}
		}
	}
#endif

#ifdef	DOVECOT_LOG
#if	defined(SITES_ENABLED_DIR) || defined(AUTH_LOG)
	else if((dport == 110) || (dport == 993)) {
#else
	if((dport == 110) || (dport == 993)) {
#endif
		FILE *p;
		int failures = 0;
		char s[100], c[200];

		/*printf("POP3 from %s\n", ipv4tostr(s, saddr));*/
		sprintf(c, "tail -20 %s|fgrep %s|fgrep Aborted|fgrep dovecot",
			DOVECOT_LOG, ipv4tostr(s, saddr));

		p = popen(c, "r");
		if(p != NULL) {
			char l[222];

			while(fgets(l, sizeof(l), p) != NULL) {
				failures++;
				/*fputs(l, stdout);*/
				/*
				 * Can't break, gets Broken Pipe from grep
				 */
				/*break;*/
			}
			pclose(p);
			if(failures >= max_failures) {
				strcpy(virusname, "Dovecot attack");
				malware_type = "Dovecot attack";
				v->infected = 1;
			}
		}
	}
#endif

#ifdef	CLAMD_CONF
	/* TODO: Make hostname/port configurable */
	if(!v->infected)
		v->infected = clamscan(v->filename, virusname, sockname, sockport);
#endif

	if(v->infected) {
		const struct hostent *h;
		struct in_addr src, dest;
		char s[MAXHOSTNAMELEN + 1], d[MAXHOSTNAMELEN + 1];

		kill_route(saddr);

		memcpy(&src, &saddr.i, sizeof(struct in_addr));
		h = gethostbyaddr(&src, sizeof(src), AF_INET);

		if(h)
			strncpy(s, h->h_name, sizeof(s) - 1);
		else
			(void)ipv4tostr(s, saddr);

		memcpy(&dest, &daddr.i, sizeof(struct in_addr));
		h = gethostbyaddr(&dest, sizeof(src), AF_INET);

		if(h)
			strncpy(d, h->h_name, sizeof(d) - 1);
		else
			(void)ipv4tostr(d, daddr);

		if(verbose) {
			if(isdigit(s[0]))
				printf("%s is sending a copy of %s to port %d\n", s,
					virusname, dport);
			else {
				struct in_addr in_addr;

				in_addr.s_addr = saddr.i;
				printf("%s (%s) is sending a copy of %s to port %d\n",
					s, inet_ntoa(in_addr), virusname, dport);
			}
		}
		syslog(LOG_NOTICE, "%s FOUND: %s is sending a copy of %s to port %d",
			malware_type, s, virusname, dport);

	}
	return v->infected;
}

/*
 * TODO: Read portsentry.conf for this, if possible
 * FIXME: Port to systems other than iptables
 *
 * Note that addr is in host order
 */
static void
kill_route(union ip_addr addr_host_order)
{
	pid_t pid;
	int status;
	char addr[128];

	if((!droproutes) && (!killprograms))
		return;

	(void)ipv4tostr(addr, addr_host_order);

	if(iswhitelisted(&addr_host_order)) {
		if(verbose >= 2)
			fprintf(stderr, "Not dropping whitelisted address %s\n",
				addr);
		return;
	}

	switch(pid = fork()) {
		case -1:
			perror("fork");
			return;
		case 0:
			/*close(0);
			close(1);
			close(2);
			open("/dev/null", O_RDONLY);
			open("/dev/null", O_WRONLY);
			dup(1);*/

			if(killprograms) {
				FILE *pin;
#ifdef	HAVE_NETSTAT_WIDE
				pin = popen("netstat -pWnt", "r");
				if(pin != NULL) {
					char buf[128];

					while(fgets(buf, sizeof(buf), pin) != NULL) {
						char *ptr;

						/*
						 * FIXME: This checks that the
						 *	IP addr is the same,
						 *	but not the port, so
						 *	we could kill a wrong
						 *	connection, but since
						 *	the other end is nasty
						 *	does that matter?
						 */
						if(strstr(buf, addr) == NULL)
							continue;

						ptr = strstr(buf, " ESTABLISHED ");
						if(ptr == NULL)
							continue;

						if(verbose >= 3)
							fputs(buf, stdout);
						pid = (pid_t)atoi(&ptr[13]);
						if(pid) {
							if(sacredlist || verbose) {
								char *p;

								ptr = strchr(ptr, '/');
								if(ptr) {
									p = strchr(++ptr, '\n');
									if(p)
										*p = '\0';
								} else
									ptr = NULL;
							} else
								ptr = NULL;

							if(sacredlist) {
								const struct sacredlist *s;

								for(s = sacredlist; s; s = s->next)
									if(strstr(ptr, s->program)) {
										if(verbose >= 2)
											printf("Not dropping sacred program %s\n",
												s->program);
										break;
									}
								if(s)
									continue;
							}
							if(kill(pid, SIGTERM) < 0)
								perror("kill");
							if(verbose) {
								if(ptr)
									printf("Terminating process %d (%s)\n", (int)pid, ptr);
								else
									printf("Terminating process %d\n", (int)pid);
							}
							sleep(1);
							kill(pid, SIGKILL);
						} else
							fprintf(stderr, "Can't find pid in %s", buf);
					}
					pclose(pin);
				}
#else
				pin = popen("lsof -i4TCP -n +c15", "r");
				if(pin != NULL) {
					pid_t lastpid = 0;
					char buf[128];

					/*
					 * lsof -n DOESN'T stop hostnames on the command line, so it's useless
					 * for filtering
					 */
					while(fgets(buf, sizeof(buf), pin) != NULL) {
						char *ptr;

						/*
						 * FIXME: This checks that the
						 *	IP addr is the same,
						 *	but not the port, so
						 *	we could kill a wrong
						 *	connection, but since
						 *	the other end is nasty
						 *	does that matter?
						 */
						if(strstr(buf, addr) == NULL)
							continue;

						if(strstr(buf, "(ESTABLISHED)") == NULL)
							continue;

						if(verbose >= 3)
							fputs(buf, stdout);
						for(ptr = buf; *ptr && !isdigit(*ptr); ptr++)
							;
						if(!*ptr) {
							fprintf(stderr, "Can't find pid in %s", buf);
							continue;
						}
						pid = (pid_t)atoi(ptr);
						if(pid) {
							if(pid == lastpid)
								continue;
							lastpid = pid;
							if(sacredlist) {
								const struct sacredlist *s;

								for(s = sacredlist; s; s = s->next)
									if(strncmp(ptr, s->program, strlen(s->program)) == 0) {
										if(verbose >= 2)
											printf("Not dropping sacred program %s\n",
												s->program);
										break;
									}
								if(s)
									continue;
							}
							if(kill(pid, SIGTERM) < 0)
								perror("kill");
							if(verbose) {
								if(ptr) {
									printf("Terminating process %d (", (int)pid);
									for(ptr = buf; !isspace(*ptr); ptr++)
										putchar(*ptr);
									fputs(")\n", stdout);
								} else
									printf("Terminating process %d\n", (int)pid);
							}
							sleep(1);
							kill(pid, SIGKILL);
						} else
							fprintf(stderr, "Can't find pid in %s", buf);
					}
					pclose(pin);
				}
#endif
			}
			if(!droproutes)
				exit(0);

			if(execl("/sbin/iptables", "iptables", "-I", "INPUT", "-s", addr, "-j", "DROP", (char *)NULL) < 0) {
				perror("/sbin/iptables");
				_exit(errno);
			}
			/*NOTREACHED*/
		default:
			if(droproutes && verbose)
				printf("Blocking traffic from %s\n", addr);

			if(waitpid(pid, &status, 0) < 0)
				perror("wait");
			else if(WEXITSTATUS(status) == 0)
				syslog(LOG_INFO, "Kill host %s", addr);
			else
				fputs("iptables drop failed\n", stderr);
	}
}

static void
allow_route(union ip_addr addr_host_order)
{
	pid_t pid;
	int status;
	char addr[128];

	if(!droproutes)
		return;

	(void)ipv4tostr(addr, addr_host_order);

	if(iswhitelisted(&addr_host_order)) {
		if(verbose >= 2)
			fprintf(stderr, "No need to allow whitelisted address %s\n",
				addr);
		return;
	}

	switch(pid = fork()) {
		case -1:
			perror("fork");
			return;
		case 0:
			/*close(0);
			close(1);
			close(2);
			open("/dev/null", O_RDONLY);
			open("/dev/null", O_WRONLY);
			dup(1);*/
			if(execl("/sbin/iptables", "iptables", "-D", "INPUT", "-s", addr, "-j", "DROP", (char *)NULL) < 0) {
				perror("/sbin/iptables");
				_exit(errno);
			}
			/*NOTREACHED*/
		default:
			if(verbose)
				printf("Allowing traffic from %s\n", addr);
			if(waitpid(pid, &status, 0) < 0)
				perror("wait");
			else if(WEXITSTATUS(status) == 0)
				syslog(LOG_INFO, "Accept host %s", addr);
			else
				fputs("iptables accept failed\n", stderr);
	}
}

static void
onexit(void)
{
	if(stopping)
		return;

	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);

	stopping = 1;

#ifdef	CLAMD_CONF
	close_clamd_socket();
#endif
}

#ifdef	CLAMD_CONF
/*
 * 0 for CLEAN or ERROR
 * FIXME: ERROR should be configurable to assume CLEAN or not
 */
static int
clamscan(const char *file, char *virusname, const char *socketpath, in_port_t port)
{
	int s, len;
	char *ptr;
	char buf[255];

	assert(file != NULL);


	if(socketpath[0] == '/')
		/* UNIX domain */
		s = unix_socket(socketpath);
	else {
		/* Internet domain */
#ifdef	DEBUG
		syslog(LOG_DEBUG, "Connecting to %s on port %d", socketpath, port);
#endif
		s = ip_socket(socketpath, port);
	}

	virusname[0] = '\0';

	if(s < 0) {
		syslog(LOG_ERR, "Couldn't to connect to clamd server %s", socketpath);
		fprintf(stderr, "Couldn't to connect to clamd server %s\n", socketpath);
		return 0;
	}

	snprintf(buf, sizeof(buf) - 1, "zSCAN %.255s", file);
#ifdef	DEBUG
	syslog(LOG_DEBUG, "%s", buf);
#endif

	len = strlen(buf) + 1;
	if(send_data(s, buf, len, socketpath) != len) {
		/*
		 * Most likely clamd has been restarted
		 */
		syslog(LOG_ERR, "Failed to send %d bytes in %s to clamd on %s", len, file, socketpath);
		fprintf(stderr, "Failed to send %d bytes in %s to clamd on %s\n", len, file, socketpath);
		close_clamd_socket();
		return 0;
	}

	/* Allow 5 minutes to read the data */
	len = recv_data(s, 5 * 60, buf, sizeof(buf));

	if(len <= 0) {
		syslog(LOG_ERR, "No response from clamd (len = %d)", len);
		close_clamd_socket();
		return 0;
	}
	buf[len] = '\0';

#ifdef	DEBUG
	syslog(LOG_DEBUG, "%s", buf);
#endif

	if((ptr = strchr(buf, '\n')) != NULL)
		*ptr = '\0';

	if((ptr = strstr(buf, "FOUND")) != NULL) {
		/*
		 * Remove the "FOUND" word, and the space before it
		 */
		*--ptr = '\0';

		/* skip over 'id: ' at the start */
		if((ptr = strrchr(buf, ':')) != NULL) {
			ptr += 2;
			/* skip over 'stream/filename: ' at the start */
			if((ptr = strrchr(ptr, ':')) != NULL)
				ptr += 2;
			else
				ptr = buf;
		} else
			ptr = buf;

		strcpy(virusname, ptr);

		return 1;
	}

	return 0;
}

static int
unix_socket(const char *socket_name)
{
	struct sockaddr_un sa;

	if(clamd_socket)
		return clamd_socket;

	if((clamd_socket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		clamd_socket = 0;
		return -1;
	}

	memset(&sa, '\0', sizeof(sa));
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, socket_name);

	if(connect(clamd_socket, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(clamd_socket);
		clamd_socket = 0;
		return -1;
	}
	if(send_data(clamd_socket, "zIDSESSION", 11, socket_name) != 11) {
		close(clamd_socket);
		clamd_socket = 0;
		return -1;
	}

	return clamd_socket;
}

static int
ip_socket(const char *hostname, in_port_t portnum)
{
	struct sockaddr_in sa;

	if(clamd_socket)
		return clamd_socket;

	memset(&sa, '\0', sizeof(sa));
	if(inet_aton(hostname, &sa.sin_addr) == 0) {
		/*
		 * TODO: looking this up each time is inneficient - add cache
		 */
		const struct hostent *h = gethostbyname(hostname);

		if(h == NULL) {
			fprintf(stderr, "Unknown host %s\n", hostname);
			syslog(LOG_NOTICE, "Unknown host %s", hostname);
			clamd_socket = 0;
			return -1;
		}
		memcpy(&sa.sin_addr, h->h_addr, sizeof(sa.sin_addr));
	}
	if((clamd_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		clamd_socket = 0;
		return -1;
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(portnum);

	if(connect(clamd_socket, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("connect");
		close(clamd_socket);
		clamd_socket = 0;
		return -1;
	}
	if(send_data(clamd_socket, "zIDSESSION", 11, NULL) != 11) {
		close(clamd_socket);
		clamd_socket = 0;
		return -1;
	}

	return clamd_socket;
}

static void
close_clamd_socket(void)
{
	if(clamd_socket == 0)
		return;

#ifdef	SHUT_RD
	shutdown(clamd_socket, SHUT_RD);
#endif
	(void)send_data(clamd_socket, "zEND", 4, NULL);

	close(clamd_socket);

	clamd_socket = 0;
}

static int
recv_data(int s, int tsecs, char *buf, size_t len)
{
	int ret;
	fd_set rfds;
	struct timeval tv;

	if(tsecs == 0)
		return recv(s, buf, len, 0);

	FD_ZERO(&rfds);
	FD_SET(s, &rfds);

	tv.tv_sec = tsecs;
	tv.tv_usec = 0;

	ret = select(s + 1, &rfds, NULL, NULL, &tv);

	if(ret == 0) {
		/* FIXME: This happens from time to time */
		syslog(LOG_NOTICE, "Select timeout\n");
		return -1;
	} else if(ret < 0) {
		if(errno != EINTR) {
			perror("select");
			syslog(LOG_NOTICE, "select failed %s", strerror(errno));
		}
		return -1;
	}

	if(!FD_ISSET(s, &rfds)) {
		syslog(LOG_NOTICE, "Read timeout");
		return -1;
	}
	return recv(s, buf, len, 0);
}

/* cli_writen isn't exported from libclamav :-( */
static int
send_data(int sock, const void *buff, unsigned int count, const char *socketpath)
{
	int retval;
	unsigned int todo;
	const unsigned char *current;

	todo = count;
	current = (const unsigned char *)buff;

	do {
#ifdef	MSG_NOSIGNAL
		retval = send(sock, current, todo, MSG_NOSIGNAL);
#else
		retval = send(sock, current, todo, 0);
#endif
		if(retval < 0) {
			if(errno == EINTR)
				continue;
			/* FIXME:
			 * Try a recv and print the data that comes in, it
			 *	should give an indication of why the other end
			 *	has gone away
			 */
			if(verbose >= 1) {
				if(socketpath && (socketpath[0] == '/'))
					perror(socketpath);
				else
					perror("send");
				fprintf(stderr, "Sent %u of %u bytes\n",
					count - todo, count);
			}
			syslog(LOG_ERR, "send_data: write error: %s",
				strerror(errno));
			return -1;
		}
		todo -= retval;
		current += retval;
	} while (todo > 0);

	return count;
}
#endif

#include "hashtable_private.h"

static void
hashtable_iterate(struct hashtable *h, int scanthem, int forceunlink)
{
	time_t now;
	unsigned int i;

	now = time((time_t *)0);

	/*printf("hashtable_iterate %d %d\n", scanthem, forceunlink);*/

	for(i = 0; i < h->tablelength; i++) {
		struct entry *e;

		for(e = h->table[i]; e; e = e->next) {
			struct key *k = e->k;
			struct value *v = e->v;

			if(forceunlink)
				destroy(NULL, k, v);
			else {
				if((now - v->lastwritten) > timealive) {
					/*
					 * This connection is likely to be dead
					 */
					if(scanthem && v->filename)
						scan(v, k->saddr, k->daddr, k->dport);
					destroy(h, k, v);
					return;	/* the current table points are wrong */
				}
				if(scanthem && v->filename && (scan(v, k->saddr, k->daddr, k->dport) == 1)) {
					/*
					 * If it's infected, there's no need
					 * to check again
					 */
					if(v->fp)
						fclose(v->fp);
					if(unlink(v->filename) < 0)
						perror(v->filename);
					free(v->filename);
					v->filename = NULL;
					v->fp = NULL;
				}
			}
		}
	}
}

static void
destroy(struct hashtable *h, struct key *k, struct value *v)
{
	if(v->fp) {
		fclose(v->fp);
		if(unlink(v->filename) < 0)
			perror(v->filename);
		free(v->filename);
		v->filename = NULL;
		v->fp = NULL;
	}

	if(v->infected)
		allow_route(k->saddr);
	if(h) {
		v = sniff_remove(h, k);
		if(v)
			free(v);
	}
}

static const char *
ipv4tostr(char *s, union ip_addr addr_host_order)
{
#if	HAVE_INET_NTOA
	struct in_addr in_addr;

	in_addr.s_addr = addr_host_order.i;
	return strcpy(s, inet_ntoa(in_addr));
#else
	sprintf(s, "%d.%d.%d.%d",
		addr_host_order.c[0], addr_host_order.c[1],
		addr_host_order.c[2], addr_host_order.c[3]);
	return s;
#endif
}

#ifdef	CLAMD_CONF
static int
getsocknamefromclamdconf(char *buf)
{
	FILE *fin = fopen(CLAMD_CONF, "r");
	char port[6], host[MAXHOSTNAMELEN + 1];
	char line[BUFSIZ];

	if(fin == NULL) {
		perror(CLAMD_CONF);
		return 0;
	}
	port[0] = host[0] = '\0';
	while(fgets(line, sizeof(line), fin)) {
		char *ptr = strchr(line, '\n');

		if((line[0] == '#') || (line[0] == '\n'))
			continue;
		if(ptr)
			*ptr = '\0';

		if(strncasecmp(line, "LocalSocket", 11) == 0) {
			ptr = &line[11];

			while(*ptr) {
				if(!isspace(*ptr))
					break;
				ptr++;
			}

			if(*ptr && (*ptr == '/')) {
				fclose(fin);
				strcpy(buf, ptr);
				return 1;
			}
		} else if(strncasecmp(line, "TCPSocket", 9) == 0) {
			ptr = &line[9];

			while(*ptr) {
				if(!isspace(*ptr))
					break;
				ptr++;
			}

			if(*ptr && isdigit(*ptr) && (strlen(ptr) <= 5)) {
				if(host[0]) {
					fclose(fin);
					sprintf(buf, "%s:%s", host, ptr);
					return 1;
				}
				strcpy(port, ptr);
			}
		} else if(strncasecmp(line, "TCPAddr", 7) == 0) {
			ptr = &line[7];

			while(*ptr) {
				if(!isspace(*ptr))
					break;
				ptr++;
			}

			if(*ptr) {
				if(port[0]) {
					fclose(fin);
					sprintf(buf, "%s:%s", ptr, port);
					return 1;
				}
				strcpy(host, ptr);
			}
		} else if(strncasecmp(line, "Example", 7) == 0) {
			fprintf(stderr, "Please edit the example configuration file %s.\n",
				CLAMD_CONF);
			break;
		}
	}
	fclose(fin);
	fprintf(stderr, "%s: Couldn't determine how to talk to ClamAV\n", CLAMD_CONF);
	return 0;
}
#endif

static int
iswhitelisted(const union ip_addr *host_order_addr)
{
	const struct whitelist *w;
	in_addr_t naddr = htonl(host_order_addr->i);

	for(w = whitelist; w; w = w->next) {
		if(verbose >= 4)
			fprintf(stderr, "Compare 0x%x (0x%x) 0x%x (0x%x) mask 0x%x\n",
				htonl(w->addr.i), htonl(w->addr.i) & w->mask,
				naddr, naddr & w->mask, w->mask);
		if((htonl(w->addr.i) & w->mask) == (naddr & w->mask))
			return 1;
	}
	return 0;
}

#ifdef SITES_ENABLED_DIR
/*
 * FIXME: Handle configurations where sites are listed in a monolithic
 *	httpd.conf
 */
static void
setup_apache_hosts(void)
{
	DIR *dirp = opendir(SITES_ENABLED_DIR);
	const struct dirent *d;
	struct apachehosts *tail;

	if(dirp == NULL) {
		perror("Failed to open directory");
		return;
	}

	tail = NULL;
	while((d = readdir(dirp)) != NULL) {
		FILE *fin;
		char buf[BUFSIZ + 1];

		if(d->d_ino == 0 || d->d_name[0] == '.')
			continue;	/* Skip hidden and unlinked files */

		if(snprintf(buf, sizeof(buf), "%s/%s", SITES_ENABLED_DIR, d->d_name) >= sizeof(buf)) {
			fprintf(stderr, "File path too long, skipping: %s\n", d->d_name);
			continue;
		}

		fin = fopen(buf, "r");
		if(fin == NULL) {
			perror(buf);
			continue;
		}
		while(fgets(buf, sizeof(buf) - 1, fin) != NULL) {
			char *p, *q;

			/* Locate ServerName or ServerAlias */
			if((p = strstr(buf, "ServerName")) != NULL)
				p = &p[10];
			else if((p = strstr(buf, "ServerAlias")) != NULL)
				p = &p[11];
			else
				continue;

			/* Trim leading whitespace */
			while(isspace((unsigned char)*p))
				p++;

			if(*p == '\0')	/* Skip if empty */
				continue;

			if(apachehosts == NULL)
				tail = apachehosts = malloc(sizeof(struct apachehosts));
			else {
				tail->next = malloc(sizeof(struct apachehosts));
				tail = tail->next;
			}
			if(tail == NULL)
				fclose(fin);
				closedir(dirp);
				fputs("Memory allocation failure\n", stderr);
				return;
			}

			q = strchr(p, '\n');
			if(q)
				*q = '\0';
			if(verbose >= 3)
				printf("Adding apache hostname %s\n", p);
			tail->name = strdup(p);
			if(tail->name == NULL) {
				free(tail);
				fclose(fin);
				closedir(dirp);
				fputs("Memory allocation failure\n", stderr);
				return;
			}
			tail->next = NULL;
		}
		fclose(fin);
	}
	closedir(dirp);
}
#endif
