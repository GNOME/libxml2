## Process this file with automake to produce Makefile.in

SUBDIRS = doc

INCLUDES = -I@srcdir@ @CORBA_CFLAGS@ $(VERSION_FLAGS)

VERSION_FLAGS = -DLIBXML_VERSION=\"@LIBXML_VERSION@\"

noinst_PROGRAMS=tester testSAX testHTML testXPath

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
		HTMLtree.c \
		debugXML.c \
		tree.c \
		xpath.c \
		valid.c

xmlincdir = $(includedir)/gnome-xml
xmlinc_HEADERS = \
		entities.h \
		encoding.h \
		parser.h \
		HTMLparser.h \
		HTMLtree.h \
		parserInternals.h \
		debugXML.h \
		xml-error.h \
		tree.h \
		xpath.h \
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

testXPath_SOURCES=testXPath.c
testXPath_LDFLAGS = 
testXPath_DEPENDENCIES = $(DEPS)
testXPath_LDADD= $(LDADDS)

check-local: tests

testall : tests SVGtests SAXtests XPathtests

tests: HTMLtests XMLtests
HTMLtests : testHTML
	@(DIR=`pwd`; cd $(srcdir) ;  \
	  for i in test/HTML/* ; do \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f result/HTML/`basename $$i` ] ; then \
	      echo New test file `basename $$i` ; \
	      $$DIR/testHTML $$i > result/HTML/`basename $$i` ; \
	  else \
	      echo Testing `basename $$i` ; \
	      $$DIR/testHTML $$i > result.`basename $$i` ; \
	      diff result/HTML/`basename $$i` result.`basename $$i` ; \
	      $$DIR/testHTML result.`basename $$i` > result2.`basename $$i` ; \
	      diff result.`basename $$i` result2.`basename $$i` ; \
	      rm result.`basename $$i` result2.`basename $$i` ; \
	  fi ; fi ; done)

XMLtests : tester
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

XPathtests : testXPath
	@(DIR=`pwd`; cd $(srcdir) ;  \
	  for i in test/XPath/expr/* ; do \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f result/XPath/expr/`basename $$i` ] ; then \
	      echo New test file `basename $$i` ; \
	      $$DIR/testXPath -f --expr $$i > result/XPath/expr/`basename $$i` ; \
	  else \
	      echo Testing `basename $$i` ; \
	      $$DIR/testXPath -f --expr $$i > result.`basename $$i` ; \
	      diff result/XPath/expr/`basename $$i` result.`basename $$i` ; \
	      rm result.`basename $$i` ; \
	  fi ; fi ; done)
	@(DIR=`pwd`; cd $(srcdir) ;  \
	  for i in test/XPath/docs/* ; do \
	  if [ ! -d $$i ] ; then \
	  name=`basename $$i`; \
	  for j in test/XPath/tests/$$name* ; do \
	  if [ ! -d $$j ] ; then \
	  if [ ! -f result/XPath/tests/`basename $$j` ] ; then \
	      echo New test file `basename $$i` ; \
	      $$DIR/testXPath -f -i $$i $$j > result/XPath/tests/`basename $$j` ; \
	  else \
	      echo Testing `basename $$j` ; \
	      $$DIR/testXPath -f -i $$i $$j > result.`basename $$j` ; \
	      diff result/XPath/tests/`basename $$j` result.`basename $$j` ; \
	      rm result.`basename $$j` ; \
	  fi ; fi ; done ; fi ; done)

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
