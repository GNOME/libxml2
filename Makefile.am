## Process this file with automake to produce Makefile.in

noinst_PROGRAMS=tester

lib_LTLIBRARIES = libxml.la

libxml_la_SOURCES = \
		SAX.c \
		entities.c \
		error.c \
		parser.c \
		tester.c \
		tree.c


include_HEADERS = \
		entities.h \
		parser.h \
		tree.h

DEPS = $(top_builddir)/libxml.la
LDADDS = $(top_builddir)/libxml.la @Z_LIBS@

tester_SOURCES=tester.c
tester_LDFLAGS = 
tester_DEPENDENCIES = $(DEPS)
tester_LDADD= $(LDADDS)

tests : tester
	@(DIR=`pwd`; cd $(srcdir) ; for i in test/* ; do \
	  if [ ! -d $$i ] ; then \
	  if [ ! -f result/`basename $$i` ] ; then \
	      echo New test file `basename $$i` ; \
	      $$DIR/tester $$i > result/`basename $$i` ; \
	  else \
	      echo Testing `basename $$i` ; \
	      $$DIR/tester $$i > result.`basename $$i` ; \
	      diff result/`basename $$i` result.`basename $$i` ; \
	      rm result.`basename $$i` ; \
	  fi ; fi ; done)

