#ifndef error_h_
#define error_h_

#include "parser.h"

void	xmlParserError		(void *ctx,
				 const char *msg,
				 ...);
void	xmlParserWarning	(void *ctx,
				 const char *msg,
				 ...);
void	xmlParserValidityError	(void *ctx,
				 const char *msg,
				 ...);
void	xmlParserValidityWarning(void *ctx,
				 const char *msg,
				 ...);
void	xmlParserPrintFileInfo	(xmlParserInputPtr input);
void	xmlParserPrintFileContext(xmlParserInputPtr input);
#endif
