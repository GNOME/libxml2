noinst_PROGRAMS	= gjobread

INCLUDES =					\
	-I$(top_builddir) -I$(top_srcdir)	\
	-I@srcdir@

LDADD = $(top_builddir)/libxml.la @Z_LIBS@

$(srcdir)/libxml:
	-$(RM) $(srcdir)/libxml
	ln -s $(srcdir)/. $(srcdir)/libxml

$(top_builddir)/libxml.la: $(srcdir)/libxml
	(cd .. ; $(MAKE))
