EXAMPLE_DIR = $(prefix)/share/doc/libxml2-python-$(LIBXML_VERSION)/examples

PYTESTS=	\
    build.py	\
    tst.py	\
    tstxpath.py	\
    xpathext.py	\
    push.py	\
    pushSAX.py	\
    error.py	\
    serialize.py\
    validate.py	\
    tstURI.py	\
    xpathret.py	\
    xpath.py

XMLS=		\
    tst.xml	\
    valid.xml	\
    invalid.xml

EXTRA_DIST = $(PYTESTS) $(XMLS)

if WITH_PYTHON
tests: $(PYTESTS)
	-@(PYTHONPATH=".." ; export PYTHONPATH; \
	   for test in $(PYTESTS) ; do echo "-- $$test" ; $(PYTHON) $$test ; done)
else
tests:
endif

clean:
	rm -f *.pyc core

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(EXAMPLE_DIR)
	-(for test in $(PYTESTS) $(XMLS); \
	  do @INSTALL@ -m 0644 $$test $(DESTDIR)$(EXAMPLE_DIR) ; done)

