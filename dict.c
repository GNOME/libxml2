/*
 * dict.c: dictionary of reusable strings, just used to avoid allocation
 *         and freeing operations.
 *
 * Copyright (C) 2003 Daniel Veillard.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE AUTHORS AND
 * CONTRIBUTORS ACCEPT NO RESPONSIBILITY IN ANY CONCEIVABLE MANNER.
 *
 * Author: daniel@veillard.com
 */

#define IN_LIBXML
#include "libxml.h"

#include <string.h>
#include <libxml/tree.h>
#include <libxml/dict.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlerror.h>
#include <libxml/globals.h>

#define MAX_HASH_LEN 4
#define MIN_DICT_SIZE 128
#define MAX_DICT_HASH 8 * 2048

/* #define ALLOW_REMOVAL */
/* #define DEBUG_GROW */

/*
 * An entry in the dictionnary
 */
typedef struct _xmlDictEntry xmlDictEntry;
typedef xmlDictEntry *xmlDictEntryPtr;
struct _xmlDictEntry {
    struct _xmlDictEntry *next;
    xmlChar *name;
    int len;
    int valid;
};

/*
 * The entire dictionnary
 */
struct _xmlDict {
    struct _xmlDictEntry *dict;
    int size;
    int nbElems;
};

/*
 * xmlDictComputeKey:
 * Calculate the hash key
 */
static unsigned long
xmlDictComputeKey(xmlDictPtr dict, const xmlChar *name, int namelen) {
    unsigned long value = 0L;
    
    if (name == NULL) return(0);
    value += 30 * (*name);
    if (namelen > 10) {
        value += name[namelen - 1];
        namelen = 10;
    }
    switch (namelen) {
        case 10: value += name[9];
        case 9: value += name[8];
        case 8: value += name[7];
        case 7: value += name[6];
        case 6: value += name[5];
        case 5: value += name[4];
        case 4: value += name[3];
        case 3: value += name[2];
        case 2: value += name[1];
        case 1: value += name[0];
        default: break;
    }
#if 0
    while ((len++ < namelen) && ((ch = *name++) != 0)) {
	value += (unsigned long)ch;
    }
#endif
#if 0
    while ((len++ < namelen) && ((ch = *name++) != 0)) {
	value = value ^ ((value << 5) + (value >> 3) + (unsigned long)ch);
    }
#endif
    return (value % dict->size);
}

/**
 * xmlDictCreate:
 *
 * Create a new dictionary
 *
 * Returns the newly created object, or NULL if an error occured.
 */
xmlDictPtr
xmlDictCreate(void) {
    xmlDictPtr dict;
  
    dict = xmlMalloc(sizeof(xmlDict));
    if (dict) {
        dict->size = MIN_DICT_SIZE;
	dict->nbElems = 0;
        dict->dict = xmlMalloc(MIN_DICT_SIZE * sizeof(xmlDictEntry));
        if (dict->dict) {
  	    memset(dict->dict, 0, MIN_DICT_SIZE * sizeof(xmlDictEntry));
  	    return(dict);
        }
        xmlFree(dict);
    }
    return(NULL);
}

/**
 * xmlDictGrow:
 * @dict: the dictionnary
 * @size: the new size of the dictionnary
 *
 * resize the dictionnary
 *
 * Returns 0 in case of success, -1 in case of failure
 */
static int
xmlDictGrow(xmlDictPtr dict, int size) {
    unsigned long key;
    int oldsize, i;
    xmlDictEntryPtr iter, next;
    struct _xmlDictEntry *olddict;
#ifdef DEBUG_GROW
    unsigned long nbElem = 0;
#endif
  
    if (dict == NULL)
	return(-1);
    if (size < 8)
        return(-1);
    if (size > 8 * 2048)
	return(-1);

    oldsize = dict->size;
    olddict = dict->dict;
    if (olddict == NULL)
        return(-1);
  
    dict->dict = xmlMalloc(size * sizeof(xmlDictEntry));
    if (dict->dict == NULL) {
	dict->dict = olddict;
	return(-1);
    }
    memset(dict->dict, 0, size * sizeof(xmlDictEntry));
    dict->size = size;

    /*	If the two loops are merged, there would be situations where
	a new entry needs to allocated and data copied into it from 
	the main dict. So instead, we run through the array twice, first
	copying all the elements in the main array (where we can't get
	conflicts) and then the rest, so we only free (and don't allocate)
    */
    for (i = 0; i < oldsize; i++) {
	if (olddict[i].valid == 0) 
	    continue;
	key = xmlDictComputeKey(dict, olddict[i].name, olddict[i].len);
	memcpy(&(dict->dict[key]), &(olddict[i]), sizeof(xmlDictEntry));
	dict->dict[key].next = NULL;
#ifdef DEBUG_GROW
	nbElem++;
#endif
    }

    for (i = 0; i < oldsize; i++) {
	iter = olddict[i].next;
	while (iter) {
	    next = iter->next;

	    /*
	     * put back the entry in the new dict
	     */

	    key = xmlDictComputeKey(dict, iter->name, iter->len);
	    if (dict->dict[key].valid == 0) {
		memcpy(&(dict->dict[key]), iter, sizeof(xmlDictEntry));
		dict->dict[key].next = NULL;
		dict->dict[key].valid = 1;
		xmlFree(iter);
	    } else {
	    	iter->next = dict->dict[key].next;
	    	dict->dict[key].next = iter;
	    }

#ifdef DEBUG_GROW
	    nbElem++;
#endif

	    iter = next;
	}
    }

    xmlFree(olddict);

#ifdef DEBUG_GROW
    xmlGenericError(xmlGenericErrorContext,
	    "xmlDictGrow : from %d to %d, %d elems\n", oldsize, size, nbElem);
#endif

    return(0);
}

/**
 * xmlDictFree:
 * @dict: the dictionnary
 *
 * Free the hash @dict and its contents. The userdata is
 * deallocated with @f if provided.
 */
void
xmlDictFree(xmlDictPtr dict) {
    int i;
    xmlDictEntryPtr iter;
    xmlDictEntryPtr next;
    int inside_dict = 0;

    if (dict == NULL)
	return;
    if (dict->dict) {
	for(i = 0; ((i < dict->size) && (dict->nbElems > 0)); i++) {
	    iter = &(dict->dict[i]);
	    if (iter->valid == 0)
		continue;
	    inside_dict = 1;
	    while (iter) {
		next = iter->next;
		if (iter->name)
		    xmlFree(iter->name);
		if (!inside_dict)
		    xmlFree(iter);
		dict->nbElems--;
		inside_dict = 0;
		iter = next;
	    }
	    inside_dict = 0;
	}
	xmlFree(dict->dict);
    }
    xmlFree(dict);
}

/**
 * xmlDictLookup:
 * @dict: the dictionnary
 * @name: the name of the userdata
 * @len: the length of the name
 *
 * Add the @name to the hash @dict if not present.
 *
 * Returns the internal copy of the name or NULL in case of internal error
 */
const xmlChar *
xmlDictLookup(xmlDictPtr dict, const xmlChar *name, int len) {
    unsigned long key, nbi = 0;
    xmlDictEntryPtr entry;
    xmlDictEntryPtr insert;
    const xmlChar *ret;

    if ((dict == NULL) || (name == NULL) || (len <= 0))
	return(NULL);

    /*
     * Check for duplicate and insertion location.
     */
    key = xmlDictComputeKey(dict, name, len);
    if (dict->dict[key].valid == 0) {
	insert = NULL;
    } else {
	for (insert = &(dict->dict[key]); insert->next != NULL;
	     insert = insert->next) {
	    if ((insert->len == len) &&
	        (!xmlStrncmp(insert->name, name, len)))
		return(insert->name);
	    nbi++;
	}
	if ((insert->len == len) &&
	    (!xmlStrncmp(insert->name, name, len)))
	    return(insert->name);
    }

    if (insert == NULL) {
	entry = &(dict->dict[key]);
    } else {
	entry = xmlMalloc(sizeof(xmlDictEntry));
	if (entry == NULL)
	     return(NULL);
    }

    ret = entry->name = xmlStrndup(name, len);
    entry->len = len;
    entry->next = NULL;
    entry->valid = 1;


    if (insert != NULL) 
	insert->next = entry;

    dict->nbElems++;

    if ((nbi > MAX_HASH_LEN) &&
        (dict->size <= ((MAX_DICT_HASH / 2) / MAX_HASH_LEN)))
	xmlDictGrow(dict, MAX_HASH_LEN * 2 * dict->size);
    /* Note that entry may have been freed at this point by xmlDictGrow */

    return(ret);
}

/**
 * xmlDictSize:
 * @dict: the dictionnary
 *
 * Query the number of elements installed in the hash @dict.
 *
 * Returns the number of elements in the dictionnary or
 * -1 in case of error
 */
int
xmlDictSize(xmlDictPtr dict) {
    if (dict == NULL)
	return(-1);
    return(dict->nbElems);
}


