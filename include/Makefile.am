## Process this file with automake to produce Makefile.in

xmlincdir = $(includedir)

xmlinc_HEADERS = \
		libxml/SAX.h \
		libxml/entities.h \
		libxml/encoding.h \
		libxml/parser.h \
		libxml/parserInternals.h \
		libxml/xmlerror.h \
		libxml/HTMLparser.h \
		libxml/HTMLtree.h \
		libxml/debugXML.h \
		libxml/tree.h \
		libxml/list.h \
		libxml/hash.h \
		libxml/xpath.h \
		libxml/xpathInternals.h \
		libxml/xpointer.h \
		libxml/xinclude.h \
		libxml/xmlIO.h \
		libxml/xmlmemory.h \
		libxml/nanohttp.h \
		libxml/nanoftp.h \
		libxml/uri.h \
		libxml/valid.h \
		libxml/xlink.h \
		libxml/xmlversion.h

install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)$(xmlincdir) $(DESTDIR)$(xmlincdir)/libxml

EXTRA_DIST = win32config.h libxml/xmlversion.h.in
