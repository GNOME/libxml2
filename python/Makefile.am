SUBDIRS= . tests

LIBS=-L../.libs -L.. $(XML_LIBS)
INCLUDES=-I/usr/include/python$(PYTHON_VERSION) -I$(PYTHON_INCLUDES) -I$(top_srcdir)/include
SHCFLAGS=$(INCLUDES) -Wall -fPIC -g
LINK_FLAGS= -shared
DOCS_DIR = $(prefix)/share/doc/libxml2-python-$(LIBXML_VERSION)

DOCS = TODO libxml2class.txt

EXTRA_DIST = 			\
	libxml.c		\
	types.c			\
	generator.py		\
	libxml_wrap.h		\
	libxml.py		\
	libxml2-python-api.xml	\
	$(DOCS)

if WITH_PYTHON
all: _libxml.so libxml2.py

libxml2.py: $(srcdir)/libxml.py libxml2class.py
	cat $(srcdir)/libxml.py libxml2class.py > libxml2.py

_libxml.so: libxml.o libxml2-py.o types.o
	$(CC) $(LINK_FLAGS) libxml.o libxml2-py.o types.o $(LIBS) -o _libxml.so

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(PYTHON_SITE_PACKAGES)
	-@INSTALL@ -m 0644 libxml2.py $(DESTDIR)$(PYTHON_SITE_PACKAGES)
	-@INSTALL@ -m 0755 _libxml.so $(DESTDIR)$(PYTHON_SITE_PACKAGES)
	$(mkinstalldirs) $(DESTDIR)$(DOCS_DIR)
	-@(for doc in $(DOCS) ; \
	   do @INSTALL@ -m 0644 $$doc $(DESTDIR)$(DOCS_DIR) ; done)
else
all: 
endif

libxml.o: libxml.c libxml2-export.c libxml_wrap.h
	$(CC) $(SHCFLAGS) -c -o libxml.o $(srcdir)/libxml.c

types.o: types.c libxml_wrap.h
	$(CC) $(SHCFLAGS) -c -o types.o $(srcdir)/types.c

libxml2-py.o: libxml2-py.c libxml2-py.h libxml_wrap.h
	$(CC) $(SHCFLAGS) -c -o libxml2-py.o $(srcdir)/libxml2-py.c

GENERATE = generator.py
API_DESC = $(top_srcdir)/doc/libxml2-api.xml $(srcdir)/libxml2-python-api.xml
GENERATED= $(srcdir)/libxml2class.py \
           $(srcdir)/libxml2-export.c \
	   $(srcdir)/libxml2-py.c \
	   $(srcdir)/libxml2-py.h

$(GENERATED): $(srcdir)/$(GENERATE) $(API_DESC)
	cd $(srcdir) && $(PYTHON) $(GENERATE)

tests: all
	cd tests && $(MAKE) tests

clean:
	rm -f $(GENERATED) *.o _libxml.so *.pyc libxml2.py

