noinst_PROGRAMS=example1

INCLUDES = -I$(top_builddir)/include -I@srcdir@/include @THREAD_CFLAGS@ @Z_CFLAGS@
DEPS = $(top_builddir)/libxml2.la
LDADDS = @STATIC_BINARIES@ $(top_builddir)/libxml2.la @THREAD_LIBS@ @Z_LIBS@ $(ICONV_LIBS) -lm @WIN32_EXTRA_LIBADD@

EXTRA_DIST=examples.xml test1.xml

example1_SOURCES=example1.c
example1_LDFLAGS =
example1_DEPENDENCIES = $(DEPS)
example1_LDADD=  @RDL_LIBS@ $(LDADDS)

all: examples.xml index.html

examples.xml: index.py *.c
	-@($(srcdir)/index.py)

index.html: examples.xml examples.xsl
	-@(xsltproc examples.xsl examples.xml && echo "Rebuilt web page" && xmllint --valid --noout index.html)
