EXTRA_DIST=devhelp.xsl

libxml2.devhelp: devhelp.xsl $(top_srcdir)/doc/libxml2-api.xml
	-@(if [ -x $(XSLTPROC) ] ; then \
	  $(XSLTPROC) --nonet -o $(srcdir)/libxml2.devhelp devhelp.xsl $(top_srcdir)/doc/libxml2-api.xml ; fi );

all: libxml2.devhelp
