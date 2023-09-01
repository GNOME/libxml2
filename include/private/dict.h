#ifndef XML_DICT_H_PRIVATE__
#define XML_DICT_H_PRIVATE__

#define HASH_ROL(x,n) ((x) << (n) | ((x) & 0xFFFFFFFF) >> (32 - (n)))

XML_HIDDEN void
xmlInitDictInternal(void);
XML_HIDDEN void
xmlCleanupDictInternal(void);
XML_HIDDEN unsigned
xmlRandom(void);

#endif /* XML_DICT_H_PRIVATE__ */
