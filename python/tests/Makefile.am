EXAMPLE_DIR = $(prefix)/share/doc/libxml2-python-$(LIBXML_VERSION)/examples

TESTS=		\
    tst.py	\
    tstxpath.py	\
    xpathext.py	\
    push.py	\
    error.py	\
    xpath.py

XMLS=		\
    tst.xml

EXTRA_DIST = $(TESTS) $(XMLS)

if WITH_PYTHON
tests: $(TESTS)
	-@(PYTHONPATH=".." ; export PYTHONPATH; \
	   for test in $(TESTS) ; do echo "-- $$test" ; $(PYTHON) $$test ; done)
else
tests:
endif

clean:
	rm -f *.pyc core

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(EXAMPLE_DIR)
	-(for test in $(TESTS) $(XMLS); \
	  do @INSTALL@ -m 0644 $$test $(DESTDIR)$(EXAMPLE_DIR) ; done)

