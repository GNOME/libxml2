## Process this file with automake to produce Makefile.in

# The name of the module.
DOC_MODULE=libxml2-$(VERSION)

# The top-level SGML file.
DOC_MAIN_SGML_FILE=gnome-xml.sgml

# The directory containing the source code (if it contains documentation).
DOC_SOURCE_DIR=..

HTML_DIR=@HTML_DIR@

TARGET_DIR=$(HTML_DIR)/$(DOC_MODULE)/html
PAGES= architecture.html bugs.html contribs.html docs.html DOM.html \
    downloads.html entities.html example.html help.html index.html \
    interface.html intro.html library.html namespaces.html news.html \
    tree.html xmldtd.html XMLinfo.html XSLT.html
APIPAGES=APIconstructors.html APIfiles.html APIfunctions.html \
    APIsymbols.html APIchunk0.html
EXTRA_DIST=xmlcatalog_man.xml

man_MANS = xmllint.1 xmlcatalog.1

all: $(PAGES)

web: $(PAGES) $(APIPAGES)

$(PAGES): xml.html site.xsl
	-@(if [ -x $(bindir)/xsltproc ] ; then \
	  $(bindir)/xsltproc --html $(top_srcdir)/doc/site.xsl $(top_srcdir)/doc/xml.html > index.html ; fi );

$(APIPAGES): libxml2-refs.xml site.xsl api.xsl
	-@(if [ -x $(bindir)/xsltproc ] ; then \
	  $(bindir)/xsltproc --html $(top_srcdir)/doc/api.xsl $(top_srcdir)/doc/xml.html ; fi );

scan:
	gtkdoc-scan --module=libxml --source-dir=$(DOC_SOURCE_DIR) --ignore-headers="acconfig.h config.h xmlwin32version.h win32config.h trio.h triostr.h triop.h config-mac.h XMLTestPrefix2.h  XMLTestPrefix.h triodef.h trionan.h xlink.h libxml.h libxml2-py.h libxml_wrap.h xmlschemas.h xmlschemastypes.h"

templates: scan
	gtkdoc-mktmpl --module=libxml

sgml:
	gtkdoc-mkdb --module=libxml --source-dir=$(DOC_SOURCE_DIR)

xml: sgml
	if test -d xml ; then rm xml/* ; else mkdir xml ; fi
	-@(for s in sgml/*.sgml ; do name=`basename $$s .sgml` ; \
	   echo '<!DOCTYPE refentry [ <!ENTITY nbsp   "&#x00A0;"> ]>' > \
	       xml/"$$name".xml ;\
	   grep -v "^<colspec" $$s >> xml/"$$name".xml ; done)
	   
libxml2-api.xml libxml2-refs.xml: xml parsedecl.py libxml-decl.txt libxml-decl-list.txt
	-(./parsedecl.py)

api: libxml2-api.xml libxml2-refs.xml

html:
	if test -n -d html ; then mkdir html ; fi
	-cd html && gtkdoc-mkhtml libxml ../$(DOC_MAIN_SGML_FILE)

clean-local:
	rm -f *~ *.bak *.hierarchy *.signals *-unused.txt

maintainer-clean-local: clean
	rm -rf sgml html libxml-decl-list.txt libxml-decl.txt 

libxml-decl-list.txt : templates

libxml-sections.txt : scan
	cp libxml-decl-list.txt libxml-sections.txt

rebuild: libxml-sections.txt templates sgml html api

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)
	-@INSTALL@ -m 0644 $(srcdir)/xml.html $(srcdir)/encoding.html $(srcdir)/FAQ.html $(srcdir)/structure.gif $(srcdir)/DOM.gif $(srcdir)/smallfootonly.gif $(srcdir)/redhat.gif $(srcdir)/libxml.gif $(srcdir)/w3c.png $(srcdir)/Libxml2-Logo-180x168.gif $(srcdir)/Libxml2-Logo-90x34.gif $(DESTDIR)$(TARGET_DIR)
	-@INSTALL@ -m 0644 $(srcdir)/html/*.html $(DESTDIR)$(TARGET_DIR)
	-@INSTALL@ -m 0644 $(srcdir)/html/index.sgml $(DESTDIR)$(TARGET_DIR)
	-(cd $(DESTDIR); gtkdoc-fixxref --module=libxml --html-dir=$(HTML_DIR))

dist-hook:
	(cd $(srcdir) ; tar cvf - *.1 site.xsl *.html *.gif w3c.png html/*.html html/*.sgml libxml2-api.xml parsedecl.py) | (cd $(distdir); tar xf -)

.PHONY : html sgml templates scan
