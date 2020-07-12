EXTRA_PROGRAMS = html htmlSeed regexp uri schema schemaSeed xml xmlSeed
check_PROGRAMS = testFuzzer
CLEANFILES = $(EXTRA_PROGRAMS)
AM_CPPFLAGS = -I$(top_srcdir)/include
DEPENDENCIES = $(top_builddir)/libxml2.la
LDADD = $(STATIC_BINARIES) $(top_builddir)/libxml2.la $(THREAD_LIBS) $(Z_LIBS) $(LZMA_LIBS) $(ICONV_LIBS) $(M_LIBS) $(WIN32_EXTRA_LIBADD)

XML_MAX_LEN = 80000
XML_SEED_CORPUS_SRC = \
    $(top_srcdir)/test/* \
    $(top_srcdir)/test/errors/*.xml \
    $(top_srcdir)/test/errors10/*.xml \
    $(top_srcdir)/test/namespaces/* \
    $(top_srcdir)/test/valid/*.xml \
    $(top_srcdir)/test/xmlid/* \
    $(top_srcdir)/test/VC/* \
    $(top_srcdir)/test/VCM/*

testFuzzer_SOURCES = testFuzzer.c fuzz.c

tests: testFuzzer$(EXEEXT)
	@echo "## Running fuzzer tests"
	@./testFuzzer$(EXEEXT)

# XML fuzzer

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
	        if [ "$$(wc -c < $$outfile)" -gt $(XML_MAX_LEN) ]; then \
	            rm $$outfile; \
	        fi; \
	    fi; \
	done
	@touch seed/xml.stamp

xml_SOURCES = xml.c fuzz.c
xml_LDFLAGS = -fsanitize=fuzzer

fuzz-xml: xml$(EXEEXT) seed/xml.stamp
	@mkdir -p corpus/xml
	./xml$(EXEEXT) \
	    -dict=xml.dict \
	    -max_len=$(XML_MAX_LEN) \
	    -timeout=20 \
	    corpus/xml seed/xml

# HTML fuzzer

htmlSeed_SOURCES = htmlSeed.c fuzz.c

seed/html.stamp: htmlSeed$(EXEEXT)
	@mkdir -p seed/html
	@for i in $(top_srcdir)/test/HTML/*; do \
	    if [ -f $$i ]; then \
	        echo Processing seed $$i; \
	        ./htmlSeed$(EXEEXT) $$i > seed/html/$$(basename $$i); \
	    fi; \
	done
	@touch seed/html.stamp

html_SOURCES = html.c fuzz.c
html_LDFLAGS = -fsanitize=fuzzer

fuzz-html: html$(EXEEXT) seed/html.stamp
	@mkdir -p corpus/html
	./html$(EXEEXT) \
	    -dict=html.dict \
	    -max_len=1000000 \
	    -timeout=20 \
	    corpus/html seed/html

# Regexp fuzzer

regexp_SOURCES = regexp.c fuzz.c
regexp_LDFLAGS = -fsanitize=fuzzer

fuzz-regexp: regexp$(EXEEXT)
	@mkdir -p corpus/regexp
	./regexp$(EXEEXT) \
	    -dict=regexp.dict \
	    -max_len=200 \
	    -timeout=5 \
	    corpus/regexp $(srcdir)/seed/regexp

# URI fuzzer

uri_SOURCES = uri.c fuzz.c
uri_LDFLAGS = -fsanitize=fuzzer

fuzz-uri: uri$(EXEEXT)
	@mkdir -p corpus/uri
	./uri$(EXEEXT) \
	    -max_len=10000 \
	    -timeout=5 \
	    corpus/uri $(srcdir)/seed/uri

# XML Schema fuzzer

schemaSeed_SOURCES = schemaSeed.c fuzz.c

seed/schema.stamp: schemaSeed$(EXEEXT)
	@mkdir -p seed/schema
	@for i in ../test/schemas/*.xsd; do \
	    if [ -f $$i ]; then \
	        echo Processing seed $$i; \
                base=$$(basename $$i) \
	        outfile=$(abs_builddir)/seed/schema/$$base; \
                pushd $$(dirname $$i) >/dev/null; \
	        $(abs_builddir)/schemaSeed$(EXEEXT) $$base > $$outfile; \
                popd >/dev/null; \
	    fi; \
	done
	@touch seed/schema.stamp

schema_SOURCES = schema.c fuzz.c
schema_LDFLAGS = -fsanitize=fuzzer

fuzz-schema: schema$(EXEEXT) seed/schema.stamp
	@mkdir -p corpus/schema
	./schema$(EXEEXT) \
	    -dict=schema.dict \
	    -max_len=$(XML_MAX_LEN) \
	    -timeout=20 \
	    corpus/schema seed/schema

