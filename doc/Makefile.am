## Process this file with automake to produce Makefile.in

# The name of the module.
DOC_MODULE=gnome-xml

# The top-level SGML file.
DOC_MAIN_SGML_FILE=gnome-xml.sgml

# The directory containing the source code (if it contains documentation).
DOC_SOURCE_DIR=..

HTML_DIR=$(datadir)/gnome-xml/html

TARGET_DIR=$(HTML_DIR)/$(DOC_MODULE)

# htmldir = $(prefix)/html
# html_DATA = gnome-dev-info.html

scan:
	gtkdoc-scan --module=$(DOC_MODULE) --source-dir=$(DOC_SOURCE_DIR) --ignore-headers="acconfig.h config.h"

templates: scan
	gtkdoc-mktmpl --module=$(DOC_MODULE)

sgml:
	gtkdoc-mkdb --module=$(DOC_MODULE) --source-dir=$(DOC_SOURCE_DIR)

html:
	if ! test -d html ; then mkdir html ; fi
	-cd html && gtkdoc-mkhtml $(DOC_MODULE) ../$(DOC_MAIN_SGML_FILE)

clean-local:
	rm -f *~ *.bak *.hierarchy *.signals *-unused.txt

maintainer-clean-local: clean
	rm -rf sgml html $(DOC_MODULE)-decl-list.txt $(DOC_MODULE)-decl.txt 

# docdatadir = $(datadir)/aclocal
# docdata_DATA = xml.html structure.gif DOM.gif

gnome-xml-decl-list.txt : templates

gnome-xml-sections.txt : scan
	cp gnome-xml-decl-list.txt gnome-xml-sections.txt

rebuild: gnome-xml-sections.txt templates sgml html

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)
	-@INSTALL@ -m 0644 $(srcdir)/xml.html $(srcdir)/structure.gif $(srcdir)/DOM.gif $(DESTDIR)$(TARGET_DIR)
	-@INSTALL@ -m 0644 $(srcdir)/html/*.html $(DESTDIR)$(TARGET_DIR)
	-@INSTALL@ -m 0644 $(srcdir)/html/index.sgml $(DESTDIR)$(TARGET_DIR)
	-(cd $(DESTDIR); gtkdoc-fixxref --module=$(DOC_MODULE) --html-dir=$(HTML_DIR))

dist-hook:
	(cd $(srcdir) ; tar cvf - xml.html structure.gif DOM.gif html/*.html html/*.sgml) | (cd $(distdir); tar xf -)

.PHONY : html sgml templates scan
