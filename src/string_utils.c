#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "string_utils.h"

void
to_lower_case(char *string)
{
	if (!string)
		return;

	char *p = string;
	char *e = string + strlen(string);

	while (p < e)
	{
		*p = tolower(*p);
		++p;
	}

	return;
}

/*
 * Turn date string into timestamp.
 * String is of format : Sun, 12 Apr 2020 08:18:37 GMT
 */
time_t
date_string_to_timestamp(char *str)
{
	assert(str);

	char *p = NULL;
	char *q = NULL;
	char *end = NULL;
	char DOM[3];
	char t[6];
	struct tm time_st;
	size_t len = strlen(str);

	memset(&time_st, 0, sizeof(time_st));

	p = str;
	end = str + len;

	q = memchr(p, ',', (end - p));

	if (!q)
		return -1;

	if (strncasecmp("Mon", p, 3) == 0)
		time_st.tm_wday = 0;
	else if (strncasecmp("Tue", p, 3) == 0)
		time_st.tm_wday = 1;
	else if (strncasecmp("Wed", p, 3) == 0)
		time_st.tm_wday = 2;
	else if (strncasecmp("Thu", p, 3) == 0)
		time_st.tm_wday = 3;
	else if (strncasecmp("Fri", p, 3) == 0)
		time_st.tm_wday = 4;
	else if (strncasecmp("Sat", p, 3) == 0)
		time_st.tm_wday = 5;
	else if (strncasecmp("Sun", p, 3) == 0)
		time_st.tm_wday = 6;

	// GET THE DAY OF THE MONTH
	++q;

	while (*q == ' ' && q < end)
		++q;

	if (q == end)
		return -1;

	p = q;
	q = memchr(p, ' ', (end - p));

	if (!q)
		return -1;

	if (*(p+1) == '0')
		++p;

	strncpy(DOM, p, (q - p));
	DOM[(q - p)] = 0;
	time_st.tm_mday = atoi(DOM);

	p = ++q;
	q = memchr(p, ' ', (end - p));

	// GET THE MONTH OF THE YEAR
	if (strncasecmp("Jan", p, 3) == 0)
		time_st.tm_mon = 0;
	else
	if (strncasecmp("Feb", p, 3) == 0)
		time_st.tm_mon = 1;
	else
	if (strncasecmp("Mar", p, 3) == 0)
		time_st.tm_mon = 2;
	else
	if (strncasecmp("Apr", p, 3) == 0)
		time_st.tm_mon = 3;
	else
	if (strncasecmp("May", p, 3) == 0)
		time_st.tm_mon = 4;
	else
	if (strncasecmp("Jun", p, 3) == 0)
		time_st.tm_mon = 5;
	else
	if (strncasecmp("Jul", p, 3) == 0)
		time_st.tm_mon = 6;
	else
	if (strncasecmp("Aug", p, 3) == 0)
		time_st.tm_mon = 7;
	else
	if (strncasecmp("Sep", p, 3) == 0)
		time_st.tm_mon = 8;
	else
	if (strncasecmp("Oct", p, 3) == 0)
		time_st.tm_mon = 9;
	else
	if (strncasecmp("Nov", p, 3) == 0)
		time_st.tm_mon = 10;
	else
	if (strncasecmp("Dec", p, 3) == 0)
		time_st.tm_mon = 11;

	p = ++q;
	q = memchr(p, ' ', (end - p));

	if (!q)
		return -1;

	strncpy(t, p, (q - p));
	t[(q - p)] = 0;
	time_st.tm_year = (atoi(t) - 1900);

	p = ++q;
	q = memchr(p, ':', (end - p));

	if (!q)
		return -1;

	strncpy(t, p, (q - p));
	t[(q - p)] = 0;
	time_st.tm_hour = atoi(t);

	p = ++q;
	q = memchr(p, ':', (end - p));

	if (!q)
		return -1;

	strncpy(t, p, (q - p));
	t[(q - p)] = 0;
	time_st.tm_min = atoi(t);

	p = ++q;
	q = memchr(p, ' ', (end - p));

	if (!q)
		return -1;

	strncpy(t, p, (q - p));
	t[(q - p)] = 0;
	time_st.tm_sec = atoi(t);

	return (time_t)mktime(&time_st);
}
