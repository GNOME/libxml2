## Process this file with automake to produce Makefile.in

SUBDIRS = . include doc example

INCLUDES = -I@srcdir@/include -I./include @Z_CFLAGS@ @CORBA_CFLAGS@ 

noinst_PROGRAMS=testSAX testHTML testXPath testURI

bin_PROGRAMS = xmllint

bin_SCRIPTS=xml2-config

lib_LTLIBRARIES = libxml2.la
libxml2_la_LIBADD = @Z_LIBS@ -lm

libxml2_la_LDFLAGS = -version-info @LIBXML_VERSION_INFO@

libxml2_la_SOURCES = \
		SAX.c \
		entities.c \
		encoding.c \
		error.c \
		parserInternals.c \
		parser.c \
		tree.c \
		hash.c \
		list.c \
		xmlIO.c \
		xmlmemory.c \
		uri.c \
		valid.c \
		xlink.c \
		HTMLparser.c \
		HTMLtree.c \
		debugXML.c \
		xpath.c \
		xpointer.c \
		xinclude.c \
		nanohttp.c \
		nanoftp.c

DEPS = $(top_builddir)/libxml2.la
LDADDS = $(top_builddir)/libxml2.la @Z_LIBS@ -lm

man_MANS = xmllint.1 xml2-config.1 libxml.4

m4datadir = $(datadir)/aclocal
m4data_DATA = libxml.m4

xmllint_SOURCES=xmllint.c
xmllint_LDFLAGS = 
xmllint_DEPENDENCIES = $(DEPS)
xmllint_LDADD=  @RDL_LIBS@ $(LDADDS)

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

testURI_SOURCES=testURI.c
testURI_LDFLAGS = 
testURI_DEPENDENCIES = $(DEPS)
testURI_LDADD= $(LDADDS)

check-local: tests

$(srcdir)/libxml:
	-$(RM) $(srcdir)/libxml
	ln -s $(srcdir)/. $(srcdir)/libxml

install-data: $(srcdir)/libxml

$(libxml2_la_SOURCES): $(srcdir)/libxml

testall : tests SVGtests SAXtests

tests: XMLtests XMLenttests HTMLtests Validtests URItests XPathtests XPtrtests XIncludetests

HTMLtests : testHTML
	@(rm -f .memdump ; touch .memdump)
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
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/HTML/$$name result.$$name ; \
	      diff -b $(srcdir)/result/HTML/$$name.err error.$$name ; \
	      $(top_builddir)/testHTML result.$$name > result2.$$name 2>error.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name error.$$name ; \
	  fi ; fi ; done)
	@echo "##"
	@echo "## Push HTML regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/HTML/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/HTML/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/testHTML $$i > $(srcdir)/result/HTML/$$name 2>$(srcdir)/result/HTML/$$name.err ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/testHTML --push $$i > result.$$name 2> error.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/HTML/$$name result.$$name ; \
	      cut -b 1-15 $(srcdir)/result/HTML/$$name.err > errorcut.$$name; \
	      cut -b 1-15 error.$$name > errorcut2.$$name; \
	      diff -b errorcut.$$name errorcut2.$$name ; \
	      $(top_builddir)/testHTML --push result.$$name > result2.$$name 2>error.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name error.$$name errorcut.$$name errorcut2.$$name ; \
	  fi ; fi ; done)
	@echo "##"
	@echo "## HTML SAX regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/HTML/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/HTML/$$name.sax ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/testHTML --sax $$i > $(srcdir)/result/HTML/$$name.sax ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/testHTML --sax $$i > result.$$name.sax ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/HTML/$$name.sax result.$$name.sax ; \
	      rm result.$$name.sax ; \
	  fi ; fi ; done)
	@echo "##"
	@echo "## Push HTML SAX regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/HTML/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/HTML/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/testHTML --sax $$i > $(srcdir)/result/HTML/$$name.sax ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/testHTML --push --sax $$i > result.$$name.sax ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/HTML/$$name.sax result.$$name.sax ; \
	      rm result.$$name.sax ; \
	  fi ; fi ; done)


XMLtests : xmllint
	@(rm -f .memdump ; touch .memdump)
	@echo "##"
	@echo "## XML regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/xmllint $$i > $(srcdir)/result/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/xmllint $$i > result.$$name ; \
	      diff $(srcdir)/result/$$name result.$$name ; \
	      $(top_builddir)/xmllint result.$$name > result2.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name ; \
	  fi ; fi ; done)
	@echo "##"
	@echo "## XML regression tests on memory"
	@echo "##"
	@(for i in $(srcdir)/test/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/xmllint --memory $$i > $(srcdir)/result/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/xmllint --memory $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/$$name result.$$name ; \
	      $(top_builddir)/xmllint --memory result.$$name > result2.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name ; \
	  fi ; fi ; done)

XMLenttests : xmllint
	@(rm -f .memdump ; touch .memdump)
	@echo "##"
	@echo "## XML entity subst regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/noent/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/xmllint --noent $$i > $(srcdir)/result/noent/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/xmllint --noent $$i > result.$$name ; \
	      diff $(srcdir)/result/noent/$$name result.$$name ; \
	      $(top_builddir)/xmllint --noent result.$$name > result2.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name ; \
	  fi ; fi ; done)

URItests : testURI
	@(rm -f .memdump ; touch .memdump)
	@echo "##"
	@echo "## URI module regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/URI/*.data ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/URI/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/testURI -base 'http://foo.com/path/to/index.html?orig#help' < $$i > $(srcdir)/result/URI/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/testURI -base 'http://foo.com/path/to/index.html?orig#help' < $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/URI/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)
	@(for i in $(srcdir)/test/URI/*.uri ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/URI/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/testURI < $$i > $(srcdir)/result/URI/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/testURI < $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/URI/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)

XPathtests : testXPath
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
	      diff $(srcdir)/result/XPath/expr/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)
	@(for i in $(srcdir)/test/XPath/docs/* ; do \
	  if [ ! -d $$i ] ; then \
	  doc=`basename $$i`; \
	  for j in $(srcdir)/test/XPath/tests/$$doc* ; do \
	  if [ ! -f $$j ] ; then continue ; fi ; \
	  name=`basename $$j`; \
	  if [ ! -d $$j ] ; then \
	  if [ ! -f $(srcdir)/result/XPath/tests/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/testXPath -f -i $$i $$j > $(srcdir)/result/XPath/tests/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/testXPath -f -i $$i $$j > result.$$name ; \
	      diff $(srcdir)/result/XPath/tests/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done ; fi ; done)

XPtrtests : testXPath
	@(rm -f .memdump ; touch .memdump)
	@echo "##"
	@echo "## XPointer regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/XPath/docs/* ; do \
	  if [ ! -d $$i ] ; then \
	  doc=`basename $$i`; \
	  for j in $(srcdir)/test/XPath/xptr/$$doc* ; do \
	  if [ ! -f $$j ] ; then continue ; fi ; \
	  name=`basename $$j`; \
	  if [ ! -d $$j ] ; then \
	  if [ ! -f $(srcdir)/result/XPath/xptr/$$name ] ; then \
	      echo New test file $$name ; \
	      ./testXPath -xptr -f -i $$i $$j > $(srcdir)/result/XPath/xptr/$$name ; \
	  else \
	      echo Testing $$name ; \
	      ./testXPath -xptr -f -i $$i $$j > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/XPath/xptr/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done ; fi ; done)

XIncludetests : xmllint
	@echo "##"
	@echo "## XInclude regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/XInclude/docs/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/XInclude/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/xmllint --xinclude $$i > $(srcdir)/result/XInclude/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/xmllint --xinclude $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/XInclude/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)

SVGtests : xmllint
	@echo "##"
	@echo "## SVG parsing regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/SVG/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/SVG/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/xmllint $$i > $(srcdir)/result/SVG/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/xmllint $$i > result.$$name ; \
	      diff $(srcdir)/result/SVG/$$name result.$$name ; \
	      $(top_builddir)/xmllint result.$$name > result2.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name ; \
	  fi ; fi ; done)

SAXtests : testSAX
	@echo "##"
	@echo "## SAX callbacks regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/SAXresult/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/testSAX $$i > $(srcdir)/SAXresult/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/testSAX $$i > result.$$name ; \
	      diff $(srcdir)/SAXresult/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)


Validtests : xmllint
	@echo "##"
	@echo "## Validity checking regression tests"
	@echo "##"
	@(for i in $(srcdir)/test/VC/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/VC/$$name ] ; then \
	      echo New test file $$name ; \
	      $(top_builddir)/xmllint --noout --valid $$i 2> $(srcdir)/result/VC/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/xmllint --noout --valid $$i 2> result.$$name ; \
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
	      $(top_builddir)/xmllint --valid $$i > $(srcdir)/result/valid/$$name 2>$(srcdir)/result/valid/$$name.err ; \
	  else \
	      echo Testing $$name ; \
	      $(top_builddir)/xmllint --valid $$i > result.$$name 2>error.$$name ; \
	      diff $(srcdir)/result/valid/$$name result.$$name ; \
	      diff $(srcdir)/result/valid/$$name.err error.$$name ; \
	      rm result.$$name error.$$name ; \
	  fi ; fi ; done)

dist-hook: libxml.spec
	-cp libxml.spec $(distdir)
	(cd $(srcdir) ; tar -cf - --exclude CVS test result SAXresult ) | (cd $(distdir); tar xf -)

cleantar:
	@(rm -f libxslt*.tar.gz)

rpm: cleantar distcheck
	rpm -ta $(distdir).tar.gz

## We create xml2Conf.sh here and not from configure because we want
## to get the paths expanded correctly.  Macros like srcdir are given
## the value NONE in configure if the user doesn't specify them (this
## is an autoconf feature, not a bug).

confexecdir=$(libdir)
confexec_DATA = xml2Conf.sh

CLEANFILES=xml2Conf.sh

confexecdir=$(libdir)
confexec_DATA = xml2Conf.sh
EXTRA_DIST = xml2Conf.sh.in libxml.spec.in libxml.spec libxml.m4 \
             example/Makefile.am example/gjobread.c example/gjobs.xml \
	     $(man_MANS) libxml-2.0.pc.in xmlversion.h.in \
	     win32/README.MSDev win32/Makefile.mingw \
	     win32/libxml2/libxml2.dsp win32/libxml2/libxml2_so.dsp \
	     win32/libxml2/libxml2_a.dsp vms/build_libxml.com vms/config.vms

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libxml-2.0.pc

#xml2Conf.sh: xml2Conf.sh.in Makefile
### Use sed and then mv to avoid problems if the user interrupts.
#	sed -e 's?\@XML_LIBDIR\@?$(XML_LIBDIR)?g' \
#	    -e 's?\@XML_INCLUDEDIR\@?$(XML_INCLUDEDIR)?g' \
#	    -e 's?\@XML_LIBS\@?$(XML_LIBS)?g' \
#	    -e 's?\@VERSION\@?$(VERSION)?g' \
#	      < $(srcdir)/xml2Conf.sh.in > xml2Conf.tmp \
#	  && mv xml2Conf.tmp xml2Conf.sh
