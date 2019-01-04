#ifndef __EDGE_OS_LIST_H__
#define __EDGE_OS_LIST_H__

// linked list base structure
struct edge_os_list {
    // private member of the list (data of the caller is set in here_
    void *data;
    // next pointer
    struct edge_os_list *next;
};

/**
 * Base structure to implement lists
 */
struct edge_os_list_base {
    // head node in the list
    struct edge_os_list *head;

    // tail node in the list
    struct edge_os_list *tail;
};

#define EDGEOS_LIST_FOR_EACH(__base, __t) \
    for (__t = __base->head; __t; __t = __t->next)


#define EDGEOS_LIST_GET_DATAPTR(__t) (__t->data)
/**
 * @brief - initialise an empty linked list
 *
 * @param base - passed from the caller. Must be valid.
 *
 * Description-
 * 
 * initialise the head and tail nodes to NULLs.
 *
 * notes:
 * ======
 *
 * library does not fail if nullptr is passed. Caller must be careful
 * to pass a valid pointer
 */
void edge_os_list_init(struct edge_os_list_base *base);

/**
 * @brief - add element to the tail of linked list
 *
 * @param base - base pointer. Must be valid
 * @param data - data to be added to the list
 *
 * Description-
 *
 * adds an element to the tail of the linked list
 *
 * @return returns 0 on success -1 on failure
 */
int edge_os_list_add_tail(struct edge_os_list_base *base, void *data);

/**
 * @brief - free the entire list
 *
 * @param base - base pointer. Must be valid
 * @param free_callback - can be null as well
 *
 * Description-
 *
 * free all elements in the list. call the caller's specific free_callback()
 * with the data of each node, caller may free the data if allocated.
 */
void edge_os_list_free(struct edge_os_list_base *base,
                      void (*free_callback)(void *data));

/**
 * @brief - iterate over the list
 *
 * @param base - base pointer. Must be valid
 * @param list_for_callback - caller pointer. API fails if null
 * @param priv - caller specific private pointer
 *
 * Description -
 *
 * iterate over the list and call the list_for_callback with node data and caller's specific priv
 *
 * @return - returns -1 if list_for_callback is null and 0 on success
 */
int edge_os_list_for_each(struct edge_os_list_base *base,
                          void (*list_for_callback)(void *data, void *priv), void *priv);

/**
 * @brief - find an element in the list
 *
 * @param base - baes pointer. Must be valid
 * @param cmpare_cb - callback to compare data with the given data. API fails if null
 * @param given - given data to be passed to the cmpare_cb
 *
 * Description-
 *
 * iterate over the list and call userspecific cmpare_cb.
 *
 * The cmpare_cb must return 1 if comparison is success and 0 if not.
 *
 * The cmpare_cb gets the node specific data pointer and the userspecific given pointer,
 * in the callback one must convert and typecast it to their specific data structure
 *
 * @return null if element not found, data pointer if found
 */
void *edge_os_list_find_elem(struct edge_os_list_base *base,
                           int (*cmpare_cb)(void *data, void *given),
                           void *given);

/**
 * @brief - delete the element from the list
 *
 * @param base - base pointer. Must be valid
 * @param item - item to delete from the list
 * @param free_callback - free callback. null can be passed.
 *
 * Description-
 *
 * delete an element from the list and call the userspecific free_callback(),
 * if valid. user may free their data pointer
 *
 * @returns 1 on success and 0 on failure
 */
int edge_os_list_delete(struct edge_os_list_base *base,
                        void *item,
                        void (*free_callback)(void *data));

#endif

