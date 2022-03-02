## Process this file with automake to produce Makefile.in
SUBDIRS = . devhelp examples

# The top-level SGML file.
DOC_MAIN_XML_FILE=gnome-xml.xml

# The directory containing the source code (if it contains documentation).
DOC_SOURCE_DIR=..

# A file in win32 depends upon one of the doc files
WIN32_DIR=$(top_srcdir)/win32

if REBUILD_DOCS
EXTRA_DIST_wc = $(wildcard tutorial/*.html) \
    $(wildcard tutorial/*.c) \
    $(wildcard tutorial/images/*.png) \
    $(wildcard tutorial/images/callouts/*.png) \
    $(wildcard *.html) $(wildcard *.1) $(wildcard *.xsl) \
    libxml2-api.xml \
    apibuild.py xmllint.xml xmlcatalog_man.xml \
    symbols.xml
endif

# Expanded form of EXTRA_DIST_wc
#
EXTRA_DIST = \
	apibuild.py \
	checkapisym.xsl \
	libxml2-api.xml \
	symbols.xml \
	syms.xsl \
	tutorial/apa.html \
	tutorial/apb.html \
	tutorial/apc.html \
	tutorial/apd.html \
	tutorial/ape.html \
	tutorial/apf.html \
	tutorial/apg.html \
	tutorial/aph.html \
	tutorial/api.html \
	tutorial/ar01s02.html \
	tutorial/ar01s03.html \
	tutorial/ar01s04.html \
	tutorial/ar01s05.html \
	tutorial/ar01s06.html \
	tutorial/ar01s07.html \
	tutorial/ar01s08.html \
	tutorial/ar01s09.html \
	tutorial/images/blank.png \
	tutorial/images/callouts/1.png \
	tutorial/images/callouts/10.png \
	tutorial/images/callouts/2.png \
	tutorial/images/callouts/3.png \
	tutorial/images/callouts/4.png \
	tutorial/images/callouts/5.png \
	tutorial/images/callouts/6.png \
	tutorial/images/callouts/7.png \
	tutorial/images/callouts/8.png \
	tutorial/images/callouts/9.png \
	tutorial/images/caution.png \
	tutorial/images/draft.png \
	tutorial/images/home.png \
	tutorial/images/important.png \
	tutorial/images/next.png \
	tutorial/images/note.png \
	tutorial/images/prev.png \
	tutorial/images/tip.png \
	tutorial/images/toc-blank.png \
	tutorial/images/toc-minus.png \
	tutorial/images/toc-plus.png \
	tutorial/images/up.png \
	tutorial/images/warning.png \
	tutorial/includeaddattribute.c \
	tutorial/includeaddkeyword.c \
	tutorial/includeconvert.c \
	tutorial/includegetattribute.c \
	tutorial/includekeyword.c \
	tutorial/includexpath.c \
	tutorial/index.html \
	tutorial/ix01.html \
	xmlcatalog.1 \
	xmlcatalog_man.html \
	xmlcatalog_man.xml \
	xmllint.1 \
	xmllint.html \
	xmllint.xml

man_MANS = xmllint.1 xmlcatalog.1

if REBUILD_DOCS
docs: $(man_MANS)

api: libxml2-api.xml libxml2-refs.xml $(WIN32_DIR)/libxml2.def.src

web: xmllint.html xmlcatalog_man.html

$(WIN32_DIR)/libxml2.def.src: libxml2-api.xml
	-@(if [ -x $(XSLTPROC) ] ; then \
	  $(XSLTPROC) -o $(WIN32_DIR)/libxml2.def.src \
	  --nonet $(WIN32_DIR)/defgen.xsl libxml2-api.xml ; fi )

source_file_deps = \
	$(filter-out %/xmlversion.h, $(wildcard $(top_srcdir)/include/libxml/*.h)) \
	$(top_srcdir)/include/libxml/xmlversion.h.in \
	$(wildcard $(top_srcdir)/*.c)

libxml2-api.xml libxml2-refs.xml ../libxml2.syms: apibuild.py symbols.xml syms.xsl checkapisym.xsl $(source_file_deps)
	test -f $(top_srcdir)/include/libxml/xmlversion.h
	(cd $(srcdir) && ./apibuild.py)
	($(XSLTPROC) $(srcdir)/checkapisym.xsl $(srcdir)/libxml2-api.xml)
	($(XSLTPROC) -o ../libxml2.syms $(srcdir)/syms.xsl $(srcdir)/symbols.xml)
	-@(cd .. ; $(MAKE) rebuild_testapi)


xmllint.1: xmllint.xml
	-@($(XSLTPROC) --nonet xmllint.xml)

xmllint.html: xmllint.xml
	-@($(XSLTPROC) --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl xmllint.xml)

xmlcatalog.1: xmlcatalog_man.xml
	-@($(XSLTPROC) --nonet xmlcatalog_man.xml)

xmlcatalog_man.html: xmlcatalog_man.xml
	-@($(XSLTPROC) --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl xmlcatalog_man.xml)

check-extra-dist:
	for f in $(EXTRA_DIST_wc) ; do echo $$f; done | sort -u >tmp.EXTRA_DIST_wc
	for f in $(EXTRA_DIST) ;    do echo $$f; done | sort    >tmp.EXTRA_DIST
	diff -u tmp.EXTRA_DIST_wc tmp.EXTRA_DIST
	rm -f tmp.EXTRA_DIST_wc tmp.EXTRA_DIST
endif

clean-local:
	rm -f *~ *.bak *.hierarchy *.signals *-unused.txt

maintainer-clean-local: clean-local
	rm -rf libxml-decl-list.txt libxml-decl.txt 

rebuild: api docs

install-data-local: 
	$(MKDIR_P) $(DESTDIR)$(HTML_DIR)/tutorial
	-$(INSTALL) -m 0644 $(srcdir)/tutorial/*.* \
		$(DESTDIR)$(HTML_DIR)/tutorial
	$(MKDIR_P) $(DESTDIR)$(HTML_DIR)/tutorial/images
	-$(INSTALL) -m 0644 $(srcdir)/tutorial/images/*.* \
		$(DESTDIR)$(HTML_DIR)/tutorial/images
	$(MKDIR_P) $(DESTDIR)$(HTML_DIR)/tutorial/images/callouts
	-$(INSTALL) -m 0644 $(srcdir)/tutorial/images/callouts/*.* \
		$(DESTDIR)$(HTML_DIR)/tutorial/images/callouts

.PHONY: docs api web rebuild
