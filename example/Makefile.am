noinst_PROGRAMS	= gjobread

INCLUDES =					\
	-I$(top_builddir) -I$(top_srcdir)	\
	-I@srcdir@

LDADD = $(top_builddir)/libxml.la @Z_LIBS@

$(top_builddir)/libxml.la:
	(cd .. ; $(MAKE))
