EXTRA_PROGRAMS = regexp uri xml xmlSeed
check_PROGRAMS = testFuzzer
CLEANFILES = $(EXTRA_PROGRAMS)
AM_CPPFLAGS = -I$(top_srcdir)/include
DEPENDENCIES = $(top_builddir)/libxml2.la
LDADD = $(STATIC_BINARIES) $(top_builddir)/libxml2.la $(THREAD_LIBS) $(Z_LIBS) $(LZMA_LIBS) $(ICONV_LIBS) $(M_LIBS) $(WIN32_EXTRA_LIBADD)

PARSER_FUZZER_MAX_LEN = 100000
XML_SEED_CORPUS_SRC = \
    $(top_srcdir)/test/* \
    $(top_srcdir)/test/errors/*.xml \
    $(top_srcdir)/test/errors10/*.xml \
    $(top_srcdir)/test/namespaces/* \
    $(top_srcdir)/test/valid/*.xml \
    $(top_srcdir)/test/xmlid/* \
    $(top_srcdir)/test/VC/* \
    $(top_srcdir)/test/VCM/*

xmlSeed_SOURCES = xmlSeed.c fuzz.c

seed/xml.stamp: xmlSeed$(EXEEXT)
	@mkdir -p seed/xml
	@for i in $(XML_SEED_CORPUS_SRC); do \
	    if [ -f $$i ]; then \
	        echo Processing seed $$i; \
                base=$$(basename $$i) \
	        outfile=$(abs_builddir)/seed/xml/$$base; \
                pushd $$(dirname $$i) >/dev/null; \
	        $(abs_builddir)/xmlSeed$(EXEEXT) $$base > $$outfile; \
                popd >/dev/null; \
	        if [ "$$(wc -c < $$outfile)" -gt $(PARSER_FUZZER_MAX_LEN) ]; then \
	            rm $$outfile; \
	        fi; \
	    fi; \
	done
	@touch seed/xml.stamp

testFuzzer_SOURCES = testFuzzer.c fuzz.c

tests: testFuzzer$(EXEEXT)
	@echo "## Running fuzzer tests"
	@./testFuzzer$(EXEEXT)

xml_SOURCES = xml.c fuzz.c
xml_LDFLAGS = -fsanitize=fuzzer

fuzz-xml: xml$(EXEEXT) seed/xml.stamp
	@mkdir -p corpus/xml
	./xml$(EXEEXT) \
	    -dict=xml.dict \
	    -max_len=$(PARSER_FUZZER_MAX_LEN) \
	    -timeout=20 \
	    corpus/xml seed/xml

regexp_SOURCES = regexp.c fuzz.c
regexp_LDFLAGS = -fsanitize=fuzzer

fuzz-regexp: regexp$(EXEEXT)
	@mkdir -p corpus/regexp
	./regexp$(EXEEXT) \
	    -dict=regexp.dict \
	    -max_len=10000 \
	    -timeout=20 \
	    corpus/regexp $(srcdir)/seed/regexp

uri_SOURCES = uri.c fuzz.c
uri_LDFLAGS = -fsanitize=fuzzer

fuzz-uri: uri$(EXEEXT)
	@mkdir -p corpus/uri
	./uri$(EXEEXT) \
	    -max_len=10000 \
	    -timeout=2 \
	    corpus/uri $(srcdir)/seed/uri

