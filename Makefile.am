## Process this file with automake to produce Makefile.in

SUBDIRS = doc

INCLUDES = -I@srcdir@ @CORBA_CFLAGS@ $(VERSION_FLAGS)

VERSION_FLAGS = -DLIBXML_VERSION=\"@LIBXML_VERSION@\"

noinst_PROGRAMS=tester testSAX testHTML

bin_SCRIPTS=xml-config

lib_LTLIBRARIES = libxml.la

libxml_la_LDFLAGS = -version-info @LIBXML_VERSION_INFO@

libxml_la_SOURCES = \
		SAX.c \
		entities.c \
		encoding.c \
		error.c \
		parser.c \
		HTMLparser.c \
		debugXML.c \
		tree.c \
		HTMLtree.c \
		valid.c

xmlincdir = $(includedir)/gnome-xml
xmlinc_HEADERS = \
		entities.h \
		encoding.h \
		parser.h \
		HTMLparser.h \
		parserInternals.h \
		debugXML.h \
		xml-error.h \
		tree.h \
		xmlIO.h \
		valid.h

DEPS = $(top_builddir)/libxml.la
LDADDS = $(top_builddir)/libxml.la @Z_LIBS@

tester_SOURCES=tester.c
tester_LDFLAGS = 
tester_DEPENDENCIES = $(DEPS)
tester_LDADD= $(LDADDS)

testSAX_SOURCES=testSAX.c
testSAX_LDFLAGS = 
testSAX_DEPENDENCIES = $(DEPS)
testSAX_LDADD= $(LDADDS)

testHTML_SOURCES=testHTML.c
testHTML_LDFLAGS = 
testHTML_DEPENDENCIES = $(DEPS)
testHTML_LDADD= $(LDADDS)

check-local: tests

testall : tests SVGtests SAXtests

tests : tester
	@(DIR=`pwd`; cd $(srcdir) ;  \
	  for i in test/* ; do \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f result/`basename $$i` ] ; then \
	      echo New test file `basename $$i` ; \
	      $$DIR/tester $$i > result/`basename $$i` ; \
	  else \
	      echo Testing `basename $$i` ; \
	      $$DIR/tester $$i > result.`basename $$i` ; \
	      diff result/`basename $$i` result.`basename $$i` ; \
	      $$DIR/tester result.`basename $$i` > result2.`basename $$i` ; \
	      diff result.`basename $$i` result2.`basename $$i` ; \
	      rm result.`basename $$i` result2.`basename $$i` ; \
	  fi ; fi ; done)

SVGtests : tester
	@(DIR=`pwd`; cd $(srcdir) ;  \
	  for i in test/SVG/* ; do \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f result/SVG/`basename $$i` ] ; then \
	      echo New test file `basename $$i` ; \
	      $$DIR/tester $$i > result/SVG/`basename $$i` ; \
	  else \
	      echo Testing `basename $$i` ; \
	      $$DIR/tester $$i > result.`basename $$i` ; \
	      diff result/SVG/`basename $$i` result.`basename $$i` ; \
	      $$DIR/tester result.`basename $$i` > result2.`basename $$i` ; \
	      diff result.`basename $$i` result2.`basename $$i` ; \
	      rm result.`basename $$i` result2.`basename $$i` ; \
	  fi ; fi ; done)

SAXtests : testSAX
	@(DIR=`pwd`; cd $(srcdir) ;  \
	  for i in test/* ; do \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f SAXresult/`basename $$i` ] ; then \
	      echo New test file `basename $$i` ; \
	      $$DIR/testSAX $$i > SAXresult/`basename $$i` ; \
	  else \
	      echo Testing `basename $$i` ; \
	      $$DIR/testSAX $$i > result.`basename $$i` ; \
	      diff SAXresult/`basename $$i` result.`basename $$i` ; \
	      rm result.`basename $$i` ; \
	  fi ; fi ; done)

#tests : tester
#	@(for i in $(srcdir)/test/* ; do \
#	  if [ ! -d $$i ] ; then \
#	  j=`echo $$i | sed -e 's,^.*/,,'`; \
#	  if [ ! -f $(srcdir)/result/$$j ] ; then \
#	      echo New test file $$j ; \
#	      ./tester $$i > $(srcdir)/result/$$j ; \
#	  else \
#	      echo Testing $$j ; \
#	      ./tester $$i > result.$$j ; \
#	      diff $(srcdir)/result/$$j result.$$j ; \
#	      rm result.$$j ; \
#	  fi ; fi ; done)

## Put `exec' in the name because this should be installed by
## `install-exec', not `install-data'.

confexecdir=$(libdir)
confexec_DATA = xmlConf.sh

EXTRA_DIST = xmlConf.sh.in libxml.spec.in test result SAXresult

dist-hook:
	cp libxml.spec $(distdir)

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
