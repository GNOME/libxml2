LIBS=-L../.libs -L.. $(XML_LIBS)
INCLUDES=-I$(PYTHON_INCLUDES) -I$(top_srcdir)/include
SHCFLAGS=$(INCLUDES) -Wall -fPIC
LINK_FLAGS= -shared
if WITH_PYTHON
all: _libxml.so libxml2.py

libxml2.py: libxml.py libxml2class.py
	cat libxml.py libxml2class.py > libxml2.py

_libxml.so: libxml.o libxml2-py.o
	$(CC) $(LINK_FLAGS) libxml2-py.o libxml.o $(LIBS) -o _libxml.so
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
	rm -f $(GENERATED) *.o _libxml.so *.pyc
