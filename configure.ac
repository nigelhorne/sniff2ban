#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([sniff2ban], [0.17], [njh@bandsman.co.uk])
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([hashtable_private.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([m], [ceil])
AC_CHECK_LIB([pcap], [pcap_lookupdev])
AC_CHECK_LIB([socket], [bind])
AC_CHECK_LIB([nsl], [gethostent])
AC_CHECK_LIB([resolv], [res_query])

# Checks for header files.
AC_HEADER_RESOLV

# FIXME: On Solaris, pcap.h is in /usr/local/include so it may not be found
# unless CFLAGS has -I/usr/local/include
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/param.h sys/socket.h syslog.h unistd.h net/ethernet.h sys/ethernet.h netinet/ip_compat.h netinet/in_systm.h pcap.h arpa/nameser_compat.h])

AC_CHECK_HEADER([netinet/if_ether.h], AC_DEFINE([HAVE_NETINET_IF_ETHER_H],1,[netinet/if_ether.h is present]), [],
[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
])

AC_CHECK_HEADER(net/if_ether.h, AC_DEFINE([HAVE_NET_IF_ETHER_H],1,[net/if_ether.h is present]), [],
[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Linux x86_64 needs resolv.h to find res_query in -lresolv
# See Debian bug 378253.
AC_MSG_CHECKING(for res_query)
AC_TRY_LINK_FUNC(res_query, AC_MSG_RESULT(yes),
	[ AC_MSG_RESULT(no)
	saved_LIBS="$LIBS"
	LIBS="$LIBS -lresolv"
	AC_MSG_CHECKING(for res_query in -lresolv)
	AC_LINK_IFELSE([AC_LANG_SOURCE([#include <stdlib.h>
#include <resolv.h>
int main()
{
	res_query (0, 0, 0, 0, 0);
	return 0;
}]]),
	[ LIBS="$LIBS -lresolv"; AC_MSG_RESULT(yes)],
	[ LIBS="$saved_LIBS"; AC_MSG_RESULT(no)])
])

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([atexit endpwent gethostbyaddr gethostbyname inet_ntoa memset select socket strchr strdup strerror strncasecmp strrchr strstr fchown memmem])

AC_MSG_NOTICE([determining whether to use netstat or lsof for the -k flag])
AC_PATH_PROG([NETSTAT], [netstat], [no])
if test "$NETSTAT" != "no"; then
	AC_MSG_CHECKING([if $NETSTAT supports wide])
	# Some netstats (e.g. old FreeBSD) use netstat -? not --help
	if eval "($NETSTAT --help 2>&1|$GREP -- -W 2>&1 >/dev/null) ||
	    ($NETSTAT -? 2>&1|$GREP -- -W 2>&1 >/dev/null)"; then
		AC_MSG_RESULT(yes)
		AC_DEFINE([HAVE_NETSTAT_WIDE], [1], [Will use netstat -W to find programs to kill])
		AC_MSG_NOTICE([will use netstat for the -k flag])
	else
		AC_MSG_RESULT(no)
		NETSTAT="no"
	fi
fi
if test "$NETSTAT" = no; then
	AC_PATH_PROG([LSOF], [lsof], [no], [$PATH$PATH_SEPARATOR/usr/pkg/sbin$PATH_SEPARATOR/usr/sbin])
	if test "$LSOF" = "no"; then
		AC_MSG_ERROR([You must have either a netstat that supports -W or lsof installed])
	fi
	# This will only work if we're root, so don't bother
	# if eval "$LSOF -i4TCP -n +c15 2>&1>/dev/null"; then
	AC_MSG_CHECKING([if $LSOF is runnable])
	if eval "$LSOF -n +c15 2>&1 >/dev/null"; then
		AC_DEFINE([HAVE_LSOF], [1], [Will use lsof to find programs to kill])
		AC_MSG_RESULT(yes)
		AC_MSG_NOTICE([will use lsof for the -k flag])
	else
		AC_MSG_RESULT(no)
		AC_MSG_ERROR([You must have either lsof installed or a netstat which supports --wide])
	fi
fi

AC_MSG_CHECKING([location of clamd.conf])
for i in /usr/local/etc /etc /etc/clamav; do
	if test -e $i/clamd.conf; then
		CLAMD_CONF=$i/clamd.conf
		AC_DEFINE_UNQUOTED([CLAMD_CONF], "$i/clamd.conf", [ClamAV configuration file])
		break
	fi
done
if test "x$CLAMD_CONF" = "x"; then
	AC_MSG_WARN([Cannot find clamd.conf, not enabling ClamAV interface])
else
	echo $CLAMD_CONF
fi

AC_ARG_ENABLE(
	ssh-scanning,
	AC_HELP_STRING([--enable-ssh-scanning],
			[ enable SSH scanning]), [
		echo YOU SHOULD NOT ENABLE SSH SCANNING FOR NOW
		AC_MSG_CHECKING([location of auth.log])
		AUTH_LOG=
		for i in /etc/syslog.conf /etc/rsyslog.conf; do
			if test -e $i; then
				RES=`egrep '^auth' $i 2>/dev/null`
				if test $? -eq 0; then
					AUTH_LOG=`echo $RES|awk '{ print $2 }'`
					AC_DEFINE_UNQUOTED([AUTH_LOG], "$AUTH_LOG", [Syslog authentiction messages])
				fi
			fi
		done

		if test "x$AUTH_LOG" = "x" && [ test -f /etc/syslog-ng/syslog-ng.conf ]; then
			RES=`fgrep auth.log /etc/syslog-ng/syslog-ng.conf 2>/dev/null`
			if test $? -eq 0; then
				AUTH_LOG=`echo $RES|awk '{ print $4 }' | perl -e 'my $s = <STDIN>; $s =~ s/.*?"(.*?)".*/$1/; print $s'`
				AC_DEFINE_UNQUOTED([AUTH_LOG], "$AUTH_LOG", [Syslog authentication messages])
			fi
		fi

		if test "x$AUTH_LOG" = "x"; then
			AC_MSG_WARN([Cannot determine location of auth.log])
		else
			echo $AUTH_LOG
		fi
])

AC_ARG_ENABLE(
	dovecot-scanning,
	AC_HELP_STRING([--enable-dovecot-scanning=FILE],
			[ enable Dovecot scanning, FILE is the log file e.g. /var/log/syslog]), [
		ac_enable_dovecot_scanning=$enableval

		if test $ac_enable_dovecot_scanning != "no"; then
			DOVECOT_LOG=$ac_enable_dovecot_scanning

			AC_MSG_CHECKING(that $DOVECOT_LOG exists)

			if test -f $DOVECOT_LOG; then
				AC_MSG_RESULT(yes)
				AC_DEFINE_UNQUOTED([DOVECOT_LOG], "$DOVECOT_LOG", [Dovecot authentication messages])
			else
				AC_MSG_ERROR($DOVECOT_LOG not found)
			fi
		fi
])

AC_ARG_ENABLE(
	smtp-scanning,
	AC_HELP_STRING([--enable-smtp-scanning=FILE],
			[ enable SMTP scanning, FILE is the log file e.g. /var/log/mail.log]), [
		ac_enable_smtp_scanning=$enableval

		if test $ac_enable_smtp_scanning != "no"; then
			SMTP_LOG=$ac_enable_smtp_scanning

			AC_MSG_CHECKING(that $SMTP_LOG exists)

			if test -f $SMTP_LOG; then
				AC_MSG_RESULT(yes)
				AC_DEFINE_UNQUOTED([SMTP_LOG], "$SMTP_LOG", [SMTP authentication messages])
			else
				AC_MSG_ERROR($SMTP_LOG not found)
			fi
		fi
])

echo building $PACKAGE_NAME for $target_os

case "$target_os" in
linux*)
	AC_DEFINE([C_LINUX], 1, [Target is Linux])
	;;
esac

AC_HEADER_RESOLV

AC_CHECK_TYPE([struct iphdr], AC_DEFINE(HAVE_STRUCT_IPHDR, 1, [Have struct iphdr in netinet/ip.h]), , [#include <netinet/ip.h>])

AC_CHECK_TYPE(sig_t, AC_DEFINE([HAVE_SIG_T], 1, [Signal functions use sig_t]), , [#include <signal.h>])
if test "x$ac_cv_type_sig_t" != x""yes; then
	AC_CHECK_TYPE(__sighandler_t, AC_DEFINE([HAVE_SIGHANDLER_T], 1, [Signal functions use __sighandler_t]), , [#include <signal.h>])
fi

# AC_CHECK_FILES([/etc/apache2/http.conf /etc/http/conf/http.conf])
AC_ARG_ENABLE(
	http-scanning,
	AC_HELP_STRING([--enable-http-scanning=DIR],
			[ enable HTTP scanning, DIR is the Apache2 sites-enabled directory]), [

	ac_enable_http_scanning=$enableval

	if test $ac_enable_http_scanning != "no"; then
		SITES_ENABLED_DIR=$ac_enable_http_scanning

		AC_MSG_CHECKING(that $SITES_ENABLED_DIR directory exists)

		# make sure that a well known include file exists
		if test -d $SITES_ENABLED_DIR; then
			AC_MSG_RESULT(yes)
		else
			AC_MSG_ERROR($SITES_ENABLED_DIR not found)
		fi
	fi
])

AC_SUBST([SITES_ENABLED_DIR])

if test x"$ac_enable_http_scanning" = "x"; then
	ac_enable_http_scanning=no
fi

if test $ac_enable_http_scanning != "no"; then
	AC_DEFINE_UNQUOTED([SITES_ENABLED_DIR], "$SITES_ENABLED_DIR", [Apache2 sites enabled dir])
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
