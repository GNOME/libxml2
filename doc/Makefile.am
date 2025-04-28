## Process this file with automake to produce Makefile.in
nobase_dist_doc_DATA = \
	xmlcatalog.html \
	xmllint.html

dist_man_MANS = xml2-config.1 xmllint.1 xmlcatalog.1

EXTRA_DIST = \
	libxml2-api.xml \
	xmlcatalog.xml \
	xmllint.xml \
	meson.build

DOCBOOK_HTML = http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl

rebuild:
	cd $(srcdir) && $(XSLTPROC) --nonet xmllint.xml
	cd $(srcdir) && $(XSLTPROC) --nonet -o xmllint.html $(DOCBOOK_HTML) xmllint.xml
	cd $(srcdir) && $(XSLTPROC) --nonet xmlcatalog.xml
	cd $(srcdir) && $(XSLTPROC) --nonet -o xmlcatalog.html $(DOCBOOK_HTML) xmlcatalog.xml

.PHONY: rebuild
