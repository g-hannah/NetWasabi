#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include "../include/string_utils.h"

#define ALIGN_SIZE(s) (((s) + 0xf) & ~(0xf))

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
	char DOM[16];
	char t[16];
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

char *
str_replace(char *s, char *replace, char *replacement)
{
	assert(s);
	assert(replace);
	assert(replacement);

	char *p, *q, *e;
	char *result;
	size_t r1len = strlen(replace);
	size_t r2len = strlen(replacement);
	size_t alloclen = 1024;
	size_t inlen = strlen(s);
	size_t currentlen;
	int diff;
	off_t off;

	if (strlen(s) > alloclen)
		alloclen *= 2;

	result = calloc(alloclen, 1);
	if (!result)
		return NULL;

	strncpy(result, s, inlen);
	e = result + inlen;
	*e = 0;

	diff = r1len - r2len;
	if (diff < 0)
		diff *= -1;

	const int longer = (r2len > r1len);

	p = q = result;

	while (1)
	{
		p = strstr(q, replace);
		if (!p || p > e)
			break;

		off = (p - result);
		currentlen = (e - result);

		if (longer)
		{
			if ((currentlen + diff) >= alloclen)
			{
				result = realloc(result, (alloclen <<= 1));
				e = result + currentlen;
				p = result + off;
			}

			q = p + r1len;
			memmove((void *)((char *)q + diff), (void *)q, (e - q));
			memcpy((void *)p, (void *)replacement, r2len);
			e += diff;
			*e = 0;

			q = (p += r2len);
		}
		else
		{
			q = p + r1len;
			memmove((void *)((char *)q - diff), (void *)q, (e - q));
			e -= diff;
			memset(e, 0, diff);

			if (r2len != 0)
				memcpy((void *)p, (void *)replacement, r2len);

			q = (p += r2len);
		}
	}

	currentlen = (e - result);
	result = realloc(result, currentlen + 16);

	return result;
}

char *
str_replace_regex(char *s, char *pattern, char *replacement)
{
	regex_t regex;
	regmatch_t match[1];
	int ret;
	char *p, *q, *e;
	size_t rlen = strlen(replacement);
	size_t mlen;
	size_t alloclen = 1024;
	size_t currentlen;
	size_t inlen = strlen(s);
	int longer = 0;
	int diff;
	char *result = NULL;

	if (regcomp(&regex, pattern, 0) != 0)
		return NULL;

	if (inlen > alloclen)
		alloclen = ALIGN_SIZE(inlen+1);

	result = calloc(alloclen, 1);
	if (!result)
		return NULL;

	strcpy(result, s);
	e = result + inlen;
	currentlen = inlen;

	while (1)
	{
		ret = regexec(&regex, result, 1, match, 0);
		if (ret)
			break;

		mlen = match[0].rm_eo - match[0].rm_so;
		if (!mlen)
			break;

		diff = rlen - mlen;
		if (diff < 0)
			diff *= -1;

		longer = (rlen > mlen);

		if (longer)
		{
			if ((currentlen + diff) >= alloclen)
			{
				result = realloc(result, (alloclen <<= 1));
				e = result + currentlen;
			}

			p = result + match[0].rm_so;
			q = p + mlen;
			memmove((void *)((char *)q + diff), (void *)q, (e - q));
			memcpy((void *)p, (void *)replacement, rlen);
			e += diff;
			*e = 0;
		}
		else
		{
			p = result + match[0].rm_so;
			q = p + mlen;

			memmove((void *)((char *)p + rlen), (void *)q, (e - q));
			e -= diff;
			memset(e, 0, diff);
			memcpy((void *)p, (void *)replacement, rlen);
		}

		fprintf(stderr, "%s\n", result);
		currentlen = (e - result);
	}

	*e = 0;
	currentlen = (e - result);
	result = realloc(result, ALIGN_SIZE(currentlen+1));
	regfree(&regex);

	return result;
}

/**
 * Return a heap-allocated string that contains
 * the part of the input string that matches
 * the regex pattern.
 */
char *
str_match(char *s, char *pattern)
{
	regex_t regex;
	regmatch_t match[1];
	char *buffer = NULL;
	int ret;
	size_t match_len;

	if (regcomp(&regex, pattern, 0) != 0)
		return NULL;

	ret = regexec(&regex, s, 1, match, 0);

	if (!ret)
	{
		match_len = (match[0].rm_eo - match[0].rm_so);
		buffer = calloc(ALIGN_SIZE(match_len), 1);
		memcpy((void *)buffer, (void *)((char *)s + match[0].rm_so), match_len);
		buffer[match_len] = 0;
	}

	regfree(&regex);

	return buffer;
}

/**
 * Return a pointer to the start of the part
 * of the input string that matches the regex
 * pattern.
 */
char *
str_find(char *s, char *pattern)
{
	regex_t regex;
	regmatch_t match[1];
	char *ptr;
	int ret;

	if (regcomp(&regex, pattern, 0) != 0)
		return NULL;

	ret = regexec(&regex, s, 1, match, 0);
	if (!ret)
	{
		ptr = (s + match[0].rm_so);
		return ptr;
	}

	return NULL;
}

static char stringified[128];
char *
to_string(int n)
{
	sprintf(stringified, "%d", n);
	return stringified;
}
#if 0
enum
{
};

char *
str_hash(char *s, int type)
{
	assert(str);	
}
#endif
