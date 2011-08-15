/*
 * list_sss.c
 *
 *  Created on: Aug 14, 2011
 *      Author: r00tkit
 */

#include "list_sss.h"


/*
**  initList()
**  initialize a list
**
*/
void initList(list_sss **list)
{
    (*list)=NULL;
}


/*
**  allocateNode()
**  allocate a new node.
**
*/

list_sss *allocateNode(TALLOC_CTX *ctx,void *data)
{
    list_sss *list;

    list = talloc(ctx, list_sss);
    if (list == NULL)
    {
        DEBUG(0, ("Node allocation failed"));
        return  NULL;
    }

    list->data=data;
    list->next=NULL;

    return (list);
}

/*
**  appendNode()
**  appends a node to the end of a list
*/

void appendNode(TALLOC_CTX * ctx,list_sss **head,void * data)
{
    list_sss *tmp,*new;
    new = allocateNode(ctx,data);
    if (is_empty_list(*head) == TRUE)
    {
        (*head)=new;
    }
    else
    {
        for (tmp=(*head); tmp->next != NULL; tmp=tmp->next);
        tmp->next=new;
    }
}


/*
**  is_empty_list()
**  check if a list variable is NULL
**
*/

Bool is_empty_list(list_sss *list)
{
    return ((list == NULL) ? TRUE : FALSE);
}

/*
**  delNode()
**  remove a node from a list
**
*/
int delNode(list_sss **head,list_sss *node)
{
    if (is_empty_list(*head) == TRUE)
        return LIST_SSS_ERROR;

    if ((*head) == node)
        (*head)=(*head)->next;
    else
    {
        list_sss *l;
        for (l=(*head); l != NULL && l->next != node; l=l->next);
        if (l == NULL)
            return LIST_SSS_ERROR;
        else
            l->next=node->next;
    }
    talloc_free(node);

    return LIST_SSS_SUCCESS;
}


/*
**  getNthNode()
**  get nth node in a list
*/

list_sss *getNthNode(list_sss *list,int n)
{
    list_sss *lp=NULL;
    int j=0;

    for (lp=list; lp; lp=lp->next)
    {
        j++;
        if (j == n)
        {
            return (lp);
        }
    }

    return ((list_sss *) NULL);
}


/*
**  numNodes()
**  returns number of nodes in the list
**
*/

size_t numNodes(list_sss **head)
{
    int n=0;

    list_sss  *lp;

    for (lp=(*head); lp; lp=lp->next)
    {
        n++;
    }

    return (n);
}

