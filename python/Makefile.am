# Makefile for libxml2 python library
AUTOMAKE_OPTIONS = 1.4 foreign

SUBDIRS= . tests

INCLUDES = \
	-I$(PYTHON_INCLUDES) \
	-I$(top_srcdir)/include

DOCS_DIR = $(datadir)/doc/libxml2-python-$(LIBXML_VERSION)
# libxml2class.txt is generated
DOCS = TODO

EXTRA_DIST = 			\
	libxml.c		\
	types.c			\
	setup.py		\
	setup.py.in		\
	generator.py		\
	libxml_wrap.h		\
	libxml.py		\
	libxml2-python-api.xml	\
	$(DOCS)

libxml2mod_la_LDFLAGS = -module -avoid-version -L$(top_builddir)/.libs

if WITH_PYTHON
mylibs = \
	$(top_builddir)/libxml2.la

all-local:	libxml2.py

pythondir = $(libdir)/python${PYTHON_VERSION}/site-packages
python_LTLIBRARIES = libxml2mod.la

libxml2mod_la_SOURCES = libxml.c types.c libxml2-py.c
libxml2mod_la_LIBADD = $(mylibs)

libxml2.py: $(srcdir)/libxml.py libxml2class.py
	cat $(srcdir)/libxml.py libxml2class.py > libxml2.py

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(libdir)/python${PYTHON_VERSION}/site-packages
	@INSTALL@ -m 0644 libxml2.py $(DESTDIR)$(libdir)/python${PYTHON_VERSION}/site-packages
	$(mkinstalldirs) $(DESTDIR)$(DOCS_DIR)
	@(for doc in $(DOCS) ; \
	   do @INSTALL@ -m 0644 $$doc $(DESTDIR)$(DOCS_DIR) ; done)

GENERATE = generator.py
API_DESC = $(top_srcdir)/doc/libxml2-api.xml $(srcdir)/libxml2-python-api.xml
GENERATED= $(srcdir)/libxml2class.py \
           $(srcdir)/libxml2-export.c \
	   $(srcdir)/libxml2-py.c \
	   $(srcdir)/libxml2-py.h

$(GENERATED): gen_prog

gen_prog: $(srcdir)/$(GENERATE) $(API_DESC)
	cd $(srcdir) && $(PYTHON) $(GENERATE)
	touch gen_prog

$(libxml2mod_la_OBJECTS): $(GENERATED)

else
all: 
endif
tests test: all
	cd tests && $(MAKE) tests

clean:
	rm -f $(GENERATED) *.o _libxml.so *.pyc libxml2.py gen_prog

