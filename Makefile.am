## Process this file with automake to produce Makefile.in

SUBDIRS = doc

INCLUDES = -I@srcdir@ @Z_CFLAGS@ @CORBA_CFLAGS@ $(VERSION_FLAGS)

VERSION_FLAGS = -DLIBXML_VERSION=\"@LIBXML_VERSION@\"

noinst_PROGRAMS=tester testSAX testHTML testXPath

bin_SCRIPTS=xml-config

lib_LTLIBRARIES = libxml.la
libxml_la_LIBADD = @Z_LIBS@

libxml_la_LDFLAGS = -version-info @LIBXML_VERSION_INFO@ @Z_LIBS@

libxml_la_SOURCES = \
		SAX.c \
		entities.c \
		encoding.c \
		error.c \
		parser.c \
		parserold.c \
		HTMLparser.c \
		HTMLtree.c \
		debugXML.c \
		tree.c \
		xpath.c \
		xmlIO.c \
		xmlmemory.c \
		nanohttp.c \
		nanoftp.c \
		valid.c \
		xlink.c \
		uri.c

xmlincdir = $(includedir)/gnome-xml
xmlinc_HEADERS = \
		SAX.h \
		entities.h \
		encoding.h \
		parser.h \
		parserInternals.h \
		xml-error.h \
		HTMLparser.h \
		HTMLtree.h \
		debugXML.h \
		tree.h \
		xpath.h \
		xmlIO.h \
		xmlmemory.h \
		nanohttp.h \
		nanoftp.h \
		valid.h \
		xlink.h \
		uri.h

DEPS = $(top_builddir)/libxml.la
LDADDS = $(top_builddir)/libxml.la @M_LIBS@

tester_SOURCES=tester.c
tester_LDFLAGS = 
tester_DEPENDENCIES = $(DEPS)
tester_LDADD=  @RDL_LIBS@ $(LDADDS)

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

testall : tests SVGtests SAXtests XPathtests XMLenttests

tests: XMLtests HTMLtests Validtests

HTMLtests : testHTML
	@echo "##"
	@echo "## HTML regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/HTML/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/HTML/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/testHTML $$i > $(srcdir)/result/HTML/$$name 2>$(srcdir)/result/HTML/$$name.err ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/testHTML $$i > result.$$name 2> error.$$name ; \
	      diff $(srcdir)/result/HTML/$$name result.$$name ; \
	      diff $(srcdir)/result/HTML/$$name.err error.$$name ; \
	      $(top_builddir)/testHTML result.$$name > result2.$$name 2>error.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name error.$$name ; \
	  fi ; fi ; done)

XMLtests : tester
	@(rm -f .memdump ; touch .memdump)
	@echo "##"
	@echo "## XML regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/tester $$i > $(srcdir)/result/$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/tester $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/$$name result.$$name ; \
	      $(top_builddir)/tester result.$$name > result2.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name ; \
	  fi ; fi ; done)

XMLenttests : tester
	@(rm -f .memdump ; touch .memdump)
	@echo "##"
	@echo "## XML entity subst regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/noent/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/tester --noent $$i > $(srcdir)/result/noent/$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/tester --noent $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/noent/$$name result.$$name ; \
	      $(top_builddir)/tester --noent result.$$name > result2.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name ; \
	  fi ; fi ; done)

XPathtests : testXPath
	@(rm -f .memdump ; touch .memdump)
	@echo "##"
	@echo "## XPath regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/XPath/expr/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/XPath/expr/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/testXPath -f --expr $$i > $(srcdir)/result/XPath/expr/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/testXPath -f --expr $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/XPath/expr/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)
	@(for i in $(srcdir)/test/XPath/docs/* ; do \
	  if [ ! -d $$i ] ; then \
	  doc=`basename $$i`; \
	  for j in $(srcdir)/test/XPath/tests/$$doc* ; do \
	  name=`basename $$j`; \
	  if [ ! -d $$j ] ; then \
	  if [ ! -f $(srcdir)/result/XPath/tests/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/testXPath -f -i $$i $$j > $(srcdir)/result/XPath/tests/$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/testXPath -f -i $$i $$j > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/XPath/tests/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done ; fi ; done)

SVGtests : tester
	@(rm -f .memdump ; touch .memdump)
	@echo "##"
	@echo "## SVG parsing regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/SVG/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/SVG/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/tester $$i > $(srcdir)/result/SVG/$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/tester $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/SVG/$$name result.$$name ; \
	      $(top_builddir)/tester result.$$name > result2.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name ; \
	  fi ; fi ; done)

SAXtests : testSAX
	@(rm -f .memdump ; touch .memdump)
	@echo "##"
	@echo "## SAX callbacks regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/SAXresult/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/testSAX $$i > $(srcdir)/SAXresult/$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/testSAX $$i > result.$$name ; \
	      diff $(srcdir)/SAXresult/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)


Validtests : tester
	@(rm -f .memdump ; touch .memdump)
	@echo "##"
	@echo "## Validity checking regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/VC/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/VC/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/tester --noout --valid $$i 2> $(srcdir)/result/VC/$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/tester --noout --valid $$i 2> result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/VC/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)
	@echo "##"
	@echo "## Valid documents regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/valid/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/valid/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/tester --valid $$i > $(srcdir)/result/valid/$$name 2>$(srcdir)/result/valid/$$name.err ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/tester --valid $$i > result.$$name 2>error.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/valid/$$name result.$$name ; \
	      diff $(srcdir)/result/valid/$$name.err error.$$name ; \
	      rm result.$$name error.$$name ; \
	  fi ; fi ; done)

dist-hook: libxml.spec
	-cp libxml.spec $(distdir)
	(cd $(srcdir) ; tar -cf - --exclude CVS test result SAXresult ) | (cd $(distdir); tar xf -)

## We create xmlConf.sh here and not from configure because we want
## to get the paths expanded correctly.  Macros like srcdir are given
## the value NONE in configure if the user doesn't specify them (this
## is an autoconf feature, not a bug).

confexecdir=$(libdir)
confexec_DATA = xmlConf.sh

CLEANFILES=xmlConf.sh

confexecdir=$(libdir)
confexec_DATA = xmlConf.sh
EXTRA_DIST = xmlConf.sh.in libxml.spec.in libxml.spec \
             example/Makefile.am example/gjobread.c example/gjobs.xml \
	     libxml.pc.in

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libxml.pc

xmlConf.sh: xmlConf.sh.in Makefile
## Use sed and then mv to avoid problems if the user interrupts.
	sed -e 's?\@XML_LIBDIR\@?$(XML_LIBDIR)?g' \
	    -e 's?\@XML_INCLUDEDIR\@?$(XML_INCLUDEDIR)?g' \
	    -e 's?\@XML_LIBS\@?$(XML_LIBS)?g' \
	    -e 's?\@VERSION\@?$(VERSION)?g' \
	      < $(srcdir)/xmlConf.sh.in > xmlConf.tmp \
	  && mv xmlConf.tmp xmlConf.sh

$(srcdir)/libxml:
	-$(RM) -f $(srcdir)/libxml
	ln -s $(srcdir)/. $(srcdir)/libxml

install-data-local:
	-mkdir -p $(DESTDIR)$(xmlincdir)
	-(cd $(DESTDIR)$(xmlincdir) && ln -s . libxml)

$(libxml_la_SOURCES): $(srcdir)/libxml
