#ifndef __STRING_UTILS_H__
#define __STRING_UTILS_H__ 1

#include <sys/types.h>
#include <time.h>

void to_lower_case(char *);
time_t date_string_to_timestamp(char *);
char *str_replace(char *str, char *replace, char *replacement);
char *str_replace_regex(char *str, char *pattern, char *replacement);
char *str_match(char *str, char *pattern);
char *str_find(char *str, char *pattern);
char *to_string(int);

#endif /* !defined __STRING_UTILS_H__ */
