#include <stdio.h>

#define IN_LIBXML
#include "libxml/xmlexports.h"

XMLPUBFUN int hello_world()
{
  printf("Success!\n");
  return 0;
}
