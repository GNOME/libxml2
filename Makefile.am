## Process this file with automake to produce Makefile.in

noinst_PROGRAMS=tester

lib_LTLIBRARIES = libxml_0.10.la

libxml_0_10_la_SOURCES = \
		xml_entities.c \
		xml_parser.c \
		xml_tree.c

include_HEADERS = \
		xml_entities.h \
		xml_parser.h \
		xml_tree.h

DEPS = $(top_builddir)/libxml_0.10.la
LDADDS = $(top_builddir)/libxml_0.10.la @Z_LIBS@

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

