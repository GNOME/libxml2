PYSCRIPTS=nist-test.py ms-test.py sun-test.py
TESTDIRS=msxsdtest nisttest suntest
TARBALL=XSTC-20020116.tar.gz
TARBALLURL=http://www.w3.org/2001/05/xmlschema-test-collection/$(TARBALL)

all:

nist-test.py: nist-test-def.xml xstc-to-python.xsl
	-@(if [ -x $(bindir)/xsltproc ] ; then				\
	  echo "Rebuilding script" $@ ;					\
	  $(bindir)/xsltproc --nonet $(srcdir)/xstc-to-python.xsl	\
	                     $(srcdir)/nist-test-def.xml > $@ ;		\
	  chmod +x $@ ; fi )

ms-test.py: ms-test-def.xml xstc-to-python.xsl
	-@(if [ -x $(bindir)/xsltproc ] ; then				\
	  echo "Rebuilding script" $@ ;					\
	  $(bindir)/xsltproc --nonet $(srcdir)/xstc-to-python.xsl	\
	                     $(srcdir)/ms-test-def.xml > $@ ;		\
	  chmod +x $@ ; fi )

sun-test.py: sun-test-def.xml xstc-to-python.xsl
	-@(if [ -x $(bindir)/xsltproc ] ; then				\
	  echo "Rebuilding script" $@ ;					\
	  $(bindir)/xsltproc --nonet $(srcdir)/xstc-to-python.xsl	\
	                     $(srcdir)/sun-test-def.xml > $@ ;		\
	  chmod +x $@ ; fi )

$(TESTDIRS):
	-@(if [ ! -f $(TARBALL) ] ; then 				\
	   echo "Missing the test suite description, trying to fetch it" ;\
	   if [ -x /usr/bin/wget ] ; then 				\
	   wget $(TARBALLURL) ; 					\
	   else echo "Dont' know how to fetch $(TARBALLURL)" ; fi ; fi)
	-@(if [ -f $(TARBALL) ] ; then 					\
	   echo -n "extracting tests directories..." ;			\
	   $(TAR) -xzf $(TARBALL) $(TESTDIRS) ;				\
	   echo "done" ;						\
	   fi);

pytests: $(PYSCRIPTS) $(TESTDIRS)
	-@(if [ -x nist-test.py -a -d nisttest ] ; then 		\
	   echo "## Running NIST Schemas tests";			\
	   PYTHONPATH="$$PYTHONPATH:../python:../python/.libs:..:../libs" ;\
	   export PYTHONPATH;						\
	   $(CHECKER) $(PYTHON) nist-test.py -s -b $(srcdir) ; fi)
	-@(if [ -x sun-test.py -a -d suntest ] ; then 			\
	   echo "## Running Sun Schemas tests";				\
	   PYTHONPATH="$$PYTHONPATH:../python:../python/.libs:..:../libs" ;\
	   export PYTHONPATH;						\
	   $(CHECKER) $(PYTHON) sun-test.py -s -b $(srcdir) ; fi)
	-@(if [ -x ms-test.py -a -d msxsdtest ] ; then 			\
	   echo "## Running Microsoft Schemas tests";			\
	   PYTHONPATH="$$PYTHONPATH:../python:../python/.libs:..:../libs" ;\
	   export PYTHONPATH;						\
	   $(CHECKER) $(PYTHON) ms-test.py -s -b $(srcdir) ; fi)

tests:
	-@(if [ -x $(PYTHON) ] ; then 					\
	   $(MAKE) MAKEFLAGS+=--silent pytests ; fi);

valgrind:
	-@(if [ -x $(PYTHON) ] ; then 					\
	   echo '## Running the regression tests under Valgrind' ;	\
	   $(MAKE) CHECKER='valgrind -q' MAKEFLAGS+=--silent pytests ; fi);

clean:
	rm -f $(PYSCRIPTS) test.log

distclean:
	rm -rf $(PYSCRIPTS) $(TESTDIRS) test.log
