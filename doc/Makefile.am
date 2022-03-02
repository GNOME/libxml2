## Process this file with automake to produce Makefile.in
SUBDIRS = . devhelp examples

EXTRA_DIST_wc = $(wildcard tutorial/*.html) \
    $(wildcard tutorial/*.c) \
    $(wildcard tutorial/images/*.png) \
    $(wildcard tutorial/images/callouts/*.png) \
    $(wildcard *.html) $(wildcard *.1) $(wildcard *.xsl) \
    libxml2-api.xml \
    apibuild.py xmllint.xml xmlcatalog_man.xml \
    symbols.xml

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

DOCBOOK_HTML = http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl

rebuild:
	cd $(srcdir) && ./apibuild.py
	cd $(srcdir) && $(XSLTPROC) checkapisym.xsl libxml2-api.xml
	cd $(srcdir) && $(XSLTPROC) -o ../libxml2.syms syms.xsl symbols.xml
	cd $(srcdir) && $(XSLTPROC) -o ../win32/libxml2.def.src ../win32/defgen.xsl libxml2-api.xml
	cd $(srcdir) && $(XSLTPROC) --nonet xmllint.xml
	cd $(srcdir) && $(XSLTPROC) --nonet -o xmllint.html $(DOCBOOK_HTML) xmllint.xml
	cd $(srcdir) && $(XSLTPROC) --nonet xmlcatalog_man.xml
	cd $(srcdir) && $(XSLTPROC) --nonet -o xmlcatalog_man.html $(DOCBOOK_HTML) xmlcatalog_man.xml
	cd devhelp && $(MAKE) rebuild
	cd examples && $(MAKE) rebuild
	cd .. && $(MAKE) rebuild_testapi

check-extra-dist:
	for f in $(EXTRA_DIST_wc) ; do echo $$f; done | sort -u >tmp.EXTRA_DIST_wc
	for f in $(EXTRA_DIST) ;    do echo $$f; done | sort    >tmp.EXTRA_DIST
	diff -u tmp.EXTRA_DIST_wc tmp.EXTRA_DIST
	rm -f tmp.EXTRA_DIST_wc tmp.EXTRA_DIST

install-data-local: 
	$(MKDIR_P) $(DESTDIR)$(docdir)/tutorial
	-$(INSTALL) -m 0644 $(srcdir)/tutorial/*.* \
		$(DESTDIR)$(docdir)/tutorial
	$(MKDIR_P) $(DESTDIR)$(docdir)/tutorial/images
	-$(INSTALL) -m 0644 $(srcdir)/tutorial/images/*.* \
		$(DESTDIR)$(docdir)/tutorial/images
	$(MKDIR_P) $(DESTDIR)$(docdir)/tutorial/images/callouts
	-$(INSTALL) -m 0644 $(srcdir)/tutorial/images/callouts/*.* \
		$(DESTDIR)$(docdir)/tutorial/images/callouts

.PHONY: rebuild
