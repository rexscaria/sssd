
#ifndef LIST_SSS_H
#define LIST_SSS_H

#include <stdio.h>

#if STDC_HEADERS
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#endif

#if HAVE_STRING_H
#include <string.h>
#endif


#include <talloc.h>
#include "util/util.h"



#define LIST_SSS_SUCCESS     0
#define LIST_SSS_ERROR       -1

#ifndef TRUE
#define TRUE    1
#endif

#ifndef FALSE
#define FALSE   0
#endif

typedef int     Bool;



/*
 ** the linked list structure
 */

typedef struct _list_sss
{
    void *data;

    struct _list_sss *next;
} list_sss;

/*
 ** function prototypes
 */
void        initList            (list_sss **list);
list_sss    *allocateNode       (TALLOC_CTX *ctx,void *data);
void        appendNode          (TALLOC_CTX *ctx,list_sss **list,void * data);
int         delNode             (list_sss **list,list_sss *node);
Bool        is_empty_list       (list_sss *list);
list_sss    *getNthNode         (list_sss *list,int n);
size_t      numNodes            (list_sss **head);

#endif  /* LIST_SSS_H */
