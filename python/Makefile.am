# Makefile for libxml2 python library
AUTOMAKE_OPTIONS = 1.4 foreign

SUBDIRS= . tests

INCLUDES = \
	-I/usr/include/python$(PYTHON_VERSION) \
	-I$(PYTHON_INCLUDES) \
	-I$(top_srcdir)/include

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
mylibs = \
	$(top_builddir)/libxml2.la

all: libxml2mod.so libxml2.py

LDADD = -lxml2
CFLAGS = -Wall -g

pythondir = $(prefix)/lib/python${PYTHON_VERSION}/site-packages
python_PROGRAMS = libxml2mod.so

libxml2mod_so_SOURCES =
libxml2mod_so_LDFLAGS = $(mylibs) $(LIBS) -shared -Wl,-soname,libxml2mod.so

noinst_LTLIBRARIES = libxmlmodule.la
libxmlmodule_la_SOURCES = libxml.c types.c libxml2-py.c

libxml2mod.so: $(libxmlmodule_la_OBJECTS)
	$(LINK) -o $@ $(libxmlmodule_la_OBJECTS) $(libxml2mod_so_LDFLAGS)


libxml2.py: $(srcdir)/libxml.py libxml2class.py
	cat $(srcdir)/libxml.py libxml2class.py > libxml2.py

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(PYTHON_SITE_PACKAGES)
	-@INSTALL@ -m 0644 libxml2.py $(DESTDIR)$(PYTHON_SITE_PACKAGES)
	$(mkinstalldirs) $(DESTDIR)$(DOCS_DIR)
	-@(for doc in $(DOCS) ; \
	   do @INSTALL@ -m 0644 $$doc $(DESTDIR)$(DOCS_DIR) ; done)

GENERATE = generator.py
API_DESC = $(top_srcdir)/doc/libxml2-api.xml $(srcdir)/libxml2-python-api.xml
GENERATED= $(srcdir)/libxml2class.py \
           $(srcdir)/libxml2-export.c \
	   $(srcdir)/libxml2-py.c \
	   $(srcdir)/libxml2-py.h

$(GENERATED): $(srcdir)/$(GENERATE) $(API_DESC)
	cd $(srcdir) && $(PYTHON) $(GENERATE)

$(libxmlmodule_la_OBJECTS): $(GENERATED)

else
all: 
endif

tests: all
	cd tests && $(MAKE) tests

clean:
	rm -f $(GENERATED) *.o _libxml.so *.pyc libxml2.py

