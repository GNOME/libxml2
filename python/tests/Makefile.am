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
    regexp.py	\
    reader.py	\
    reader2.py	\
    reader3.py	\
    reader4.py	\
    reader5.py	\
    reader6.py	\
    reader7.py	\
    walker.py	\
    ctxterror.py\
    readererr.py\
    relaxng.py	\
    thread2.py \
    tstLastError.py \
    indexes.py

XMLS=		\
    tst.xml	\
    valid.xml	\
    invalid.xml

EXTRA_DIST = $(PYTESTS) $(XMLS)

if WITH_PYTHON
tests: $(PYTESTS)
	-@(PYTHONPATH="..:../.libs:$(srcdir)/.." ; export PYTHONPATH; \
	   for test in $(PYTESTS) ; do echo "-- $$test" ; $(PYTHON) $(srcdir)/$$test ; done)
else
tests:
endif

clean:
	rm -f *.pyc core

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(EXAMPLE_DIR)
	-(for test in $(PYTESTS) $(XMLS); \
	  do @INSTALL@ -m 0644 $(srcdir)/$$test $(DESTDIR)$(EXAMPLE_DIR) ; done)

