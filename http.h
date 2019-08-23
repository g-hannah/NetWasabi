#ifndef HTTP_H
#define HTTP_H 1

#include <stdint.h>
#include <time.h>

#define HTTP_OK 200u
#define HTTP_MOVED_PERMANENTLY 301u
#define HTTP_FOUND 302u
#define HTTP_BAD_REQUEST 400u
#define HTTP_UNAUTHORISED 401u
#define HTTP_FORBIDDEN 403u
#define HTTP_NOT_FOUND 404u
#define HTTP_INTERNAL_ERROR 500u
#define HTTP_BAD_GATEWAY 502u
#define HTTP_SERVICE_UNAV 503u
#define HTTP_GATEWAY_TIMEOUT 504u

#define link_is_dead(l) (l)->dead

typedef struct http_link_t
{
	int nr_refs;
	char *url;
	time_t reaped_when;
	int dead;
	struct http_link_t *next;
} http_link_t;

/**
 * for_each_http_link - iterate over linked list
 * @ptr: &http_link_t to use as a loop cursor
 * @head: the head for the list
 */
#define for_each_http_link(ptr, head) \
	for (ptr = (head)->next; ptr != (head); ptr = ptr->next)

/**
 * for_each_http_link_safe - iterate over linked list, safe to remove members
 * @ptr: &http_link_t to use as a loop cursor
 * @n: another &http_link_t to use as temp storage
 * @head: head of linked list
 */
#define for_each_http_link_safe(ptr, n, head) \
	for (ptr = (head)->next, n = ptr->next; ptr != (head); \
				ptr = n, n = ptr->next)

#define http_inc_cookies(h) (++(h)->nr_cookies)
#define http_dec_cookies(h) (--(h)->nr_cookies)
#define http_nr_cookies(h) ((h)->nr_cookies)
#define http_nr_links(h) ((h)->nr_links)
#define http_nr_requests(h) ((h)->nr_requests)

typedef struct http_state_t
{
	int nr_requests;
	char **http_cookies;
	int nr_cookies;
	int nr_links;
	http_link_t *head;
	http_link_t *tail;
} http_state_t;

#endif /* !defined HTTP_H */
