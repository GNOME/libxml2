## Process this file with automake to produce Makefile.in
#AUTOMAKE_ OPTIONS=no-dependencies

SUBDIRS = include . doc example python

INCLUDES = -I@srcdir@/include -I$(top_builddir)/include @THREAD_CFLAGS@ @Z_CFLAGS@ 

noinst_PROGRAMS=testSAX testHTML testXPath testURI testDocbook testThreads \
                testC14N

bin_PROGRAMS = xmllint xmlcatalog

bin_SCRIPTS=xml2-config

lib_LTLIBRARIES = libxml2.la
libxml2_la_LIBADD = @Z_LIBS@ $(ICONV_LIBS) -lm

libxml2_la_LDFLAGS = -version-info @LIBXML_VERSION_INFO@

if WITH_TRIO_SOURCES
libxml2_la_SOURCES = SAX.c entities.c encoding.c error.c parserInternals.c  \
		parser.c tree.c hash.c list.c xmlIO.c xmlmemory.c uri.c  \
		valid.c xlink.c HTMLparser.c HTMLtree.c debugXML.c xpath.c  \
		xpointer.c xinclude.c nanohttp.c nanoftp.c DOCBparser.c \
		catalog.c globals.c threads.c c14n.c triostr.c trio.c

else
libxml2_la_SOURCES = SAX.c entities.c encoding.c error.c parserInternals.c  \
		parser.c tree.c hash.c list.c xmlIO.c xmlmemory.c uri.c  \
		valid.c xlink.c HTMLparser.c HTMLtree.c debugXML.c xpath.c  \
		xpointer.c xinclude.c nanohttp.c nanoftp.c DOCBparser.c \
		catalog.c globals.c threads.c c14n.c

endif

DEPS = $(top_builddir)/libxml2.la
LDADDS = $(top_builddir)/libxml2.la @THREAD_LIBS@ @Z_LIBS@ $(ICONV_LIBS) -lm

man_MANS = xml2-config.1 libxml.3

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

testDocbook_SOURCES=testDocbook.c
testDocbook_LDFLAGS = 
testDocbook_DEPENDENCIES = $(DEPS)
testDocbook_LDADD= $(LDADDS)

xmlcatalog_SOURCES=xmlcatalog.c
xmlcatalog_LDFLAGS = 
xmlcatalog_DEPENDENCIES = $(DEPS)
xmlcatalog_LDADD= @RDL_LIBS@ $(LDADDS)

testXPath_SOURCES=testXPath.c
testXPath_LDFLAGS = 
testXPath_DEPENDENCIES = $(DEPS)
testXPath_LDADD= $(LDADDS)

testC14N_SOURCES=testC14N.c
testC14N_LDFLAGS = 
testC14N_DEPENDENCIES = $(DEPS)
testC14N_LDADD= $(LDADDS)

testThreads_SOURCES=testThreads.c
testThreads_LDFLAGS = 
testThreads_DEPENDENCIES = $(DEPS)
testThreads_LDADD= $(LDADDS)

testURI_SOURCES=testURI.c
testURI_LDFLAGS = 
testURI_DEPENDENCIES = $(DEPS)
testURI_LDADD= $(LDADDS)

check-local: tests

testall : tests SVGtests SAXtests

tests: XMLtests XMLenttests HTMLtests Validtests URItests XPathtests XPtrtests XIncludetests Scripttests Catatests @TEST_THREADS@
	@(cd python ; $(MAKE) tests)

valgrind:
	@echo '## Running the regression tests under Valgrind'
	@echo '## Go get a cup of coffee it is gonna take a while ...'
	$(MAKE) CHECKER='valgrind -q' tests

HTMLtests : testHTML$(EXEEXT)
	@(echo > .memdump)
	@echo "##"
	@echo "## HTML regression tests"
	@echo "##"
	-@(for i in $(srcdir)/test/HTML/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/HTML/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/testHTML $$i > $(srcdir)/result/HTML/$$name 2>$(srcdir)/result/HTML/$$name.err ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/testHTML $$i > result.$$name 2> error.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/HTML/$$name result.$$name ; \
	      diff -b $(srcdir)/result/HTML/$$name.err error.$$name ; \
	      $(CHECKER) $(top_builddir)/testHTML result.$$name > result2.$$name 2>error.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name error.$$name ; \
	  fi ; fi ; done)
	@echo "##"
	@echo "## Push HTML regression tests"
	@echo "##"
	-@(for i in $(srcdir)/test/HTML/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/HTML/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/testHTML $$i > $(srcdir)/result/HTML/$$name 2>$(srcdir)/result/HTML/$$name.err ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/testHTML --push $$i > result.$$name 2> error.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/HTML/$$name result.$$name ; \
	      cut -b 1-15 $(srcdir)/result/HTML/$$name.err > errorcut.$$name; \
	      cut -b 1-15 error.$$name > errorcut2.$$name; \
	      diff -b errorcut.$$name errorcut2.$$name ; \
	      $(CHECKER) $(top_builddir)/testHTML --push result.$$name > result2.$$name 2>error.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name error.$$name errorcut.$$name errorcut2.$$name ; \
	  fi ; fi ; done)
	@echo "##"
	@echo "## HTML SAX regression tests"
	@echo "##"
	-@(for i in $(srcdir)/test/HTML/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/HTML/$$name.sax ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/testHTML --sax $$i > $(srcdir)/result/HTML/$$name.sax ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/testHTML --sax $$i > result.$$name.sax ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/HTML/$$name.sax result.$$name.sax ; \
	      rm result.$$name.sax ; \
	  fi ; fi ; done)
	@echo "##"
	@echo "## Push HTML SAX regression tests"
	@echo "##"
	-@(for i in $(srcdir)/test/HTML/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/HTML/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/testHTML --sax $$i > $(srcdir)/result/HTML/$$name.sax ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/testHTML --push --sax $$i > result.$$name.sax ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/HTML/$$name.sax result.$$name.sax ; \
	      rm result.$$name.sax ; \
	  fi ; fi ; done)


XMLtests : xmllint$(EXEEXT)
	@(echo > .memdump)
	@echo "##"
	@echo "## XML regression tests"
	@echo "##"
	@echo "## You should see one warning on entity 'title.xml' for ent2"
	@echo "##"
	-@(for i in $(srcdir)/test/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint $$i > $(srcdir)/result/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint $$i > result.$$name ; \
	      diff $(srcdir)/result/$$name result.$$name ; \
	      $(CHECKER) $(top_builddir)/xmllint result.$$name > result2.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name ; \
	  fi ; fi ; done)
	@(echo > .memdump)
	@echo "##"
	@echo "## XML push regression tests"
	@echo "##"
	@echo "## You should see one warning on entity 'title.xml' for ent2"
	@echo "##"
	-@(for i in $(srcdir)/test/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --push $$i > $(srcdir)/result/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --push $$i > result.$$name ; \
	      diff $(srcdir)/result/$$name result.$$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --push result.$$name > result2.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name ; \
	  fi ; fi ; done)
	@echo "##"
	@echo "## XML regression tests on memory"
	@echo "##"
	@echo "## You should see two warnings on entity 'title.xml' for ent2"
	@echo "##"
	-@(for i in $(srcdir)/test/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --memory $$i > $(srcdir)/result/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --memory $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/$$name result.$$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --memory result.$$name > result2.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name ; \
	  fi ; fi ; done)

Docbtests : xmllint$(EXEEXT)
	@(echo > .memdump)
	@echo "##"
	@echo "## SGML DocBook regression tests"
	@echo "##"
	-@(for i in $(srcdir)/test/DocBook/*.sgm ; do \
	  name=`basename $$i .sgm`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/DocBook/$$name.xml ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --sgml $$i > $(srcdir)/result/DocBook/$$name.xml ; \
	      $(CHECKER) $(top_builddir)/xmllint --valid --noout $(srcdir)/result/DocBook/$$name.xml ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --sgml $$i > result.$$name ; \
	      diff $(srcdir)/result/DocBook/$$name.xml result.$$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --valid --noout result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)

XMLenttests : xmllint$(EXEEXT)
	@(echo > .memdump)
	@echo "##"
	@echo "## XML entity subst regression tests"
	@echo "##"
	-@(for i in $(srcdir)/test/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/noent/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --noent $$i > $(srcdir)/result/noent/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --noent $$i > result.$$name ; \
	      diff $(srcdir)/result/noent/$$name result.$$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --noent result.$$name > result2.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name ; \
	  fi ; fi ; done)

URItests : testURI$(EXEEXT)
	@(echo > .memdump)
	@echo "##"
	@echo "## URI module regression tests"
	@echo "##"
	-@(for i in $(srcdir)/test/URI/*.data ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/URI/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/testURI -base 'http://foo.com/path/to/index.html?orig#help' < $$i > $(srcdir)/result/URI/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/testURI -base 'http://foo.com/path/to/index.html?orig#help' < $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/URI/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)
	-@(for i in $(srcdir)/test/URI/*.uri ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/URI/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/testURI < $$i > $(srcdir)/result/URI/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/testURI < $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/URI/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)

XPathtests : testXPath$(EXEEXT)
	@(echo > .memdump)
	@echo "##"
	@echo "## XPath regression tests"
	@echo "##"
	-@(if [ "`$(top_builddir)/testXPath | grep 'support not compiled in'`" != "" ] ; \
	  then echo Skipping debug not compiled in ; exit 0 ; fi ; \
	  for i in $(srcdir)/test/XPath/expr/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/XPath/expr/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/testXPath -f --expr $$i > $(srcdir)/result/XPath/expr/$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/testXPath -f --expr $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/XPath/expr/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done ; \
	  for i in $(srcdir)/test/XPath/docs/* ; do \
	  if [ ! -d $$i ] ; then \
	  doc=`basename $$i`; \
	  for j in $(srcdir)/test/XPath/tests/$$doc* ; do \
	  if [ ! -f $$j ] ; then continue ; fi ; \
	  name=`basename $$j`; \
	  if [ ! -d $$j ] ; then \
	  if [ ! -f $(srcdir)/result/XPath/tests/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/testXPath -f -i $$i $$j > $(srcdir)/result/XPath/tests/$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/testXPath -f -i $$i $$j > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/XPath/tests/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done ; fi ; done)

XPtrtests : testXPath$(EXEEXT)
	@(echo > .memdump)
	@echo "##"
	@echo "## XPointer regression tests"
	@echo "##"
	-@(if [ "`$(top_builddir)/testXPath | grep 'support not compiled in'`" != "" ] ; \
	  then echo Skipping debug not compiled in ; exit 0 ; fi ; \
	  for i in $(srcdir)/test/XPath/docs/* ; do \
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

XIncludetests : xmllint$(EXEEXT)
	@(echo > .memdump)
	@echo "##"
	@echo "## XInclude regression tests"
	@echo "##"
	-@(for i in $(srcdir)/test/XInclude/docs/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/XInclude/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --xinclude $$i > $(srcdir)/result/XInclude/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --xinclude $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/XInclude/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)

Scripttests : xmllint$(EXEEXT)
	@(echo > .memdump)
	@echo "##"
	@echo "## Scripts regression tests"
	@echo "## Some of the base computations may be different if srcdir != ."
	@echo "##"
	-@(for i in $(srcdir)/test/scripts/*.script ; do \
	  name=`basename $$i .script`; \
	  xml=$(srcdir)/test/scripts/`basename $$i .script`.xml; \
	  if [ -f $$xml ] ; then \
	  if [ ! -f $(srcdir)/result/scripts/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --shell $$xml < $$i > $(srcdir)/result/scripts/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --shell $$xml < $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/scripts/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)

Catatests : xmlcatalog$(EXEEXT)
	@(echo > .memdump)
	@echo "##"
	@echo "## Catalog regression tests"
	@echo "##"
	-@(for i in $(srcdir)/test/catalogs/*.script ; do \
	  name=`basename $$i .script`; \
	  xml=$(srcdir)/test/catalogs/`basename $$i .script`.xml; \
	  if [ -f $$xml ] ; then \
	  if [ ! -f $(srcdir)/result/catalogs/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/xmlcatalog --shell $$xml < $$i > $(srcdir)/result/catalogs/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/xmlcatalog --shell $$xml < $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/catalogs/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)
	-@(for i in $(srcdir)/test/catalogs/*.script ; do \
	  name=`basename $$i .script`; \
	  sgml=$(srcdir)/test/catalogs/`basename $$i .script`.sgml; \
	  if [ -f $$sgml ] ; then \
	  if [ ! -f $(srcdir)/result/catalogs/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/xmlcatalog --shell $$sgml < $$i > $(srcdir)/result/catalogs/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/xmlcatalog --shell $$sgml < $$i > result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/catalogs/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)
	@echo "Add and del operations on XML Catalogs"
	-@($(CHECKER) $(top_builddir)/xmlcatalog --create --noout result/catalogs/mycatalog; \
	grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0"; \
	$(CHECKER) $(top_builddir)/xmlcatalog --noout --add public Pubid sysid result/catalogs/mycatalog; \
	grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0"; \
	$(CHECKER) $(top_builddir)/xmlcatalog --noout --add public Pubid2 sysid2 result/catalogs/mycatalog; \
	grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0"; \
	$(CHECKER) $(top_builddir)/xmlcatalog --noout --add public Pubid3 sysid3 result/catalogs/mycatalog; \
	grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0"; \
	diff result/catalogs/mycatalog.full result/catalogs/mycatalog; \
	grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0"; \
	$(CHECKER) $(top_builddir)/xmlcatalog --noout --del sysid result/catalogs/mycatalog; \
	grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0"; \
	$(CHECKER) $(top_builddir)/xmlcatalog --noout --del sysid3 result/catalogs/mycatalog; \
	grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0"; \
	$(CHECKER) $(top_builddir)/xmlcatalog --noout --del sysid2 result/catalogs/mycatalog; \
	grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0"; \
	diff result/catalogs/mycatalog.empty result/catalogs/mycatalog; \
	grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0"; \
	rm -f result/catalogs/mycatalog)

SVGtests : xmllint$(EXEEXT)
	@echo "##"
	@echo "## SVG parsing regression tests"
	@echo "##"
	-@(for i in $(srcdir)/test/SVG/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/SVG/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint $$i > $(srcdir)/result/SVG/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint $$i > result.$$name ; \
	      diff $(srcdir)/result/SVG/$$name result.$$name ; \
	      $(CHECKER) $(top_builddir)/xmllint result.$$name > result2.$$name ; \
	      diff result.$$name result2.$$name ; \
	      rm result.$$name result2.$$name ; \
	  fi ; fi ; done)

Threadtests : testThreads$(EXEEXT)
	@echo "##"
	@echo "## Threaded regression tests"
	@echo "##"
	$(CHECKER) $(top_builddir)/testThreads

SAXtests : testSAX$(EXEEXT)
	@(echo > .memdump)
	@echo "##"
	@echo "## SAX callbacks regression tests"
	@echo "##"
	-@(for i in $(srcdir)/test/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/SAXresult/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/testSAX $$i > $(srcdir)/SAXresult/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/testSAX $$i > result.$$name ; \
	      diff $(srcdir)/SAXresult/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)


Validtests : xmllint$(EXEEXT)
	@(echo > .memdump)
	@echo "##"
	@echo "## Valid documents regression tests"
	@echo "##"
	-@(for i in $(srcdir)/test/VCM/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --valid --noout --nowarning $$i ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	  fi ; done ; exit 0)
	@echo "##"
	@echo "## Validity checking regression tests"
	@echo "##"
	-@(for i in $(srcdir)/test/VC/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/VC/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --noout --valid $$i 2> $(srcdir)/result/VC/$$name ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --noout --valid $$i 2> result.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/VC/$$name result.$$name ; \
	      rm result.$$name ; \
	  fi ; fi ; done)
	@echo "##"
	@echo "## General documents valid regression tests"
	@echo "##"
	-@(for i in $(srcdir)/test/valid/* ; do \
	  name=`basename $$i`; \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f $(srcdir)/result/valid/$$name ] ; then \
	      echo New test file $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --valid $$i > $(srcdir)/result/valid/$$name 2>$(srcdir)/result/valid/$$name.err ; \
	  else \
	      echo Testing $$name ; \
	      $(CHECKER) $(top_builddir)/xmllint --valid $$i > result.$$name 2>error.$$name ; \
	      grep "MORY ALLO" .memdump  | grep -v "MEMORY ALLOCATED : 0";\
	      diff $(srcdir)/result/valid/$$name result.$$name ; \
	      diff $(srcdir)/result/valid/$$name.err error.$$name ; \
	      rm result.$$name error.$$name ; \
	  fi ; fi ; done)

dist-hook: libxml.spec
	-cp libxml.spec $(distdir)
	(cd $(srcdir) ; tar -cf - --exclude CVS win32 macos vms test result SAXresult ) | (cd $(distdir); tar xf -)

cleantar:
	@(rm -f libxml*.tar.gz COPYING.LIB)

rpm: cleantar
	@(unset CDPATH ; $(MAKE) dist && rpm -ta $(distdir).tar.gz)

## We create xml2Conf.sh here and not from configure because we want
## to get the paths expanded correctly.  Macros like srcdir are given
## the value NONE in configure if the user doesn't specify them (this
## is an autoconf feature, not a bug).

CLEANFILES=xml2Conf.sh

confexecdir=$(libdir)
confexec_DATA = xml2Conf.sh
EXTRA_DIST = xml2-config.in xml2Conf.sh.in libxml.spec.in libxml.spec \
             libxml.m4 Copyright check-xml-test-suite.py \
             example/Makefile.am example/gjobread.c example/gjobs.xml \
	     $(man_MANS) libxml-2.0.pc.in \
	     trionan.c trionan.h triostr.c triostr.h trio.c trio.h \
	     triop.h triodef.h libxml.h \
	     testThreadsWin32.c

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libxml-2.0.pc

#
# Instll the tests program sources as examples 
#
BASE_DIR=@HTML_DIR@
DOC_MODULE=libxml2-$(VERSION)
EXAMPLES_DIR=$(BASE_DIR)/$(DOC_MODULE)/examples

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(BASE_DIR)/$(DOC_MODULE)
	-@INSTALL@ -m 0644 $(srcdir)/Copyright $(DESTDIR)$(BASE_DIR)/$(DOC_MODULE)
	$(mkinstalldirs) $(DESTDIR)$(EXAMPLES_DIR)
	-@INSTALL@ -m 0644 $(srcdir)/xmllint.c $(DESTDIR)$(EXAMPLES_DIR)
	-@INSTALL@ -m 0644 $(srcdir)/testSAX.c $(DESTDIR)$(EXAMPLES_DIR)
	-@INSTALL@ -m 0644 $(srcdir)/testHTML.c $(DESTDIR)$(EXAMPLES_DIR)
	-@INSTALL@ -m 0644 $(srcdir)/testXPath.c $(DESTDIR)$(EXAMPLES_DIR)
