AUTOMAKE_OPTIONS=no-dependencies

noinst_PROGRAMS	= gjobread

INCLUDES =					\
	-I$(top_builddir) -I$(top_srcdir)	\
	-I$(top_builddir)/include		\
	-I$(top_srcdir)/include -I@srcdir@

LDADD = $(top_builddir)/libxml2.la @THREAD_LIBS@ @Z_LIBS@ $(ICONV_LIBS) -lm

