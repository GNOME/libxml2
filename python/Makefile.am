LIBS=-L../.libs -L..
INCLUDES=-I$(PYTHON_INCLUDES) -I$(top_srcdir)/include
SHCFLAGS=$(INCLUDES) -Wall -fPIC
LINK_FLAGS= $(LIBS) -shared -lxml2
if WITH_PYTHON
all: _libxml.so

_libxml.so: libxml.o libxml2-py.o
	$(CC) $(LINK_FLAGS) libxml2-py.o libxml.o -o _libxml.so
else
all: 
endif

libxml.o: libxml.c libxml2-export.c libxml_wrap.h
	$(CC) $(SHCFLAGS) -c -o libxml.o $(srcdir)/libxml.c

libxml2-py.o: libxml2-py.c libxml2-py.h libxml_wrap.h
	$(CC) $(SHCFLAGS) -c -o libxml2-py.o $(srcdir)/libxml2-py.c

GENERATE = generator.py
API_DESC = $(top_srcdir)/doc/libxml2-api.xml
GENERATED= $(srcdir)/libxml2class.py \
           $(srcdir)/libxml2-export.c \
	   $(srcdir)/libxml2-py.c \
	   $(srcdir)/libxml2-py.h

$(GENERATED): $(srcdir)/$(GENERATE) $(API_DESC)
	cd $(srcdir) && $(PYTHON) $(GENERATE)

clean:
	rm -f $(GENERATED) *.o _libxml.so
