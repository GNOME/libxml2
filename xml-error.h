#ifndef error_h_
#define error_h_

#include "parser.h"

void xmlParserError(void *ctx, const char *msg, ...);
void xmlParserWarning(void *ctx, const char *msg, ...);
#endif
