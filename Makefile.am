## Process this file with automake to produce Makefile.in

noinst_PROGRAMS=tester

bin_SCRIPTS=xml-config

lib_LTLIBRARIES = libxml.la

libxml_la_SOURCES = \
		SAX.c \
		entities.c \
		error.c \
		error.h \
		parser.c \
		tester.c \
		tree.c


xmlincdir = $(includedir)/gnome-xml
xmlinc_HEADERS = \
		entities.h \
		parser.h \
		tree.h

DEPS = $(top_builddir)/libxml.la
LDADDS = $(top_builddir)/libxml.la @Z_LIBS@

tester_SOURCES=tester.c
tester_LDFLAGS = 
tester_DEPENDENCIES = $(DEPS)
tester_LDADD= $(LDADDS)

tests : tester
	@(DIR=`pwd`; cd $(srcdir) ; for i in test/* ; do \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f result/`basename $$i` ] ; then \
	      echo New test file `basename $$i` ; \
	      $$DIR/tester $$i > result/`basename $$i` ; \
	  else \
	      echo Testing `basename $$i` ; \
	      $$DIR/tester $$i > result.`basename $$i` ; \
	      diff result/`basename $$i` result.`basename $$i` ; \
	      rm result.`basename $$i` ; \
	  fi ; fi ; done)

## Put `exec' in the name because this should be installed by
## `install-exec', not `install-data'.

confexecdir=$(libdir)
confexec_DATA = xmlConf.sh

EXTRA_DIST = xmlConf.sh.in

## We create xmlConf.sh here and not from configure because we want
## to get the paths expanded correctly.  Macros like srcdir are given
## the value NONE in configure if the user doesn't specify them (this
## is an autoconf feature, not a bug).

xmlConf.sh: xmlConf.sh.in Makefile
## Use sed and then mv to avoid problems if the user interrupts.
	sed -e 's?\@XML_LIBDIR\@?$(XML_LIBDIR)?g' \
	    -e 's?\@XML_INCLUDEDIR\@?$(XML_INCLUDEDIR)?g' \
	    -e 's?\@XML_LIBS\@?$(XML_LIBS)?g' \
	      < $(srcdir)/xmlConf.sh.in > xmlConf.tmp \
	  && mv xmlConf.tmp xmlConf.sh
