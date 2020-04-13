#ifndef __STRING_UTILS_H__
#define __STRING_UTILS_H__ 1

#include <sys/types.h>
#include <time.h>

void to_lower_case(char *);
time_t date_string_to_timestamp(char *);

#endif /* !defined __STRING_UTILS_H__ */
