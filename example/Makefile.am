AUTOMAKE_OPTIONS=no-dependencies

noinst_PROGRAMS	= gjobread

INCLUDES =					\
	-I$(top_builddir) -I$(top_srcdir)	\
	-I$(top_srcdir)/include -I@srcdir@

LDADD = $(top_builddir)/libxml2.la @Z_LIBS@ $(ICONV_LIBS) -lm

