EXAMPLE_DIR = $(datadir)/doc/libxml2-python-$(LIBXML_VERSION)/examples

PYTESTS=	\
    build.py	\
    attribs.py	\
    tst.py	\
    tstxpath.py	\
    xpathext.py	\
    push.py	\
    pushSAX.py	\
    pushSAXhtml.py \
    error.py	\
    serialize.py\
    validate.py	\
    tstURI.py	\
    cutnpaste.py\
    xpathret.py	\
    xpath.py	\
    outbuf.py	\
    inbuf.py	\
    resolver.py \
    regexp.py

XMLS=		\
    tst.xml	\
    valid.xml	\
    invalid.xml

EXTRA_DIST = $(PYTESTS) $(XMLS)

if WITH_PYTHON
tests: $(PYTESTS)
	-@(PYTHONPATH="..:../.libs" ; export PYTHONPATH; \
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

