
//#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
//#include <sys/stat.h>
//#include <fcntl.h>
#include <unistd.h>

#include "parse.h"

#define CONFIG_SIZE_MAX 32000

#define cp_is_comment(c) (*c=='#')
#define cp_is_eol(c) (*c==0x0a||*c==0x0d||*c==0x00)
#define cp_is_whitespace(c) (*c==' '||*c==0x09)
#define cp_is_sep(c) (cp_is_whitespace(c)||*c==':'||*c=='=')

#define cp_skip_whitespace(c,e) while(c<e&&cp_is_whitespace(c)){c++;} 
#define cp_skip_eol(c,e) while(c<e&&cp_is_eol(c)){c++;} 
#define cp_skip_sep(c,e) while(c<e&&cp_is_sep(c)){c++;} 

#define cp_find_eol(c,e) while(c<e&&!cp_is_eol(c)){c++;} 
#define cp_find_eot(c,e) while(c<e&&!(cp_is_eol(c)||cp_is_sep(c)||cp_is_comment(c))){c++;} 
#define cp_find_eotm(c,e) while(c<e&&!(cp_is_eol(c)||cp_is_comment(c))){c++;} 

// flip this if you ever end up having to debug this
#define CP_DEBUG(...)
//#define CP_DEBUG(...) printf(__VA_ARGS__)

/* crude config parser
 * approximates:
 *   s/#.*$//;
 *   /^\s*([^\s:=])+(?:[\s:=])+(.*)\s*$/
 * and calls cb with $1 and $2 as key/val (if any)
 * in other words
 *   dont use # in either key or value
 *   key has to be single space-less token
 */
int parse_config(int fd, ssize_t size, void (*cb)(char*,char*,void*), void* cbd)
{
	char tbuf[CONFIG_SIZE_MAX+1];
	ssize_t count;
	char *cur, *end;
	char *key, *val;

	count = read(fd, &tbuf, CONFIG_SIZE_MAX);
	if (count != size) 
	{
		CP_DEBUG("read mismatch\n");
		return(-1);
	}
	cur = &tbuf[0];
	end = cur + count;

	while (cur < end) 
	{
		key = val = NULL;
		CP_DEBUG("\nline offs %d ...", (cur-&tbuf[0]));
		cp_skip_whitespace(cur,end);

		if (cp_is_comment(cur))
		{
			CP_DEBUG(" comment");
			cp_find_eol(cur,end);
			cp_skip_eol(cur,end);
			continue;
		}
		
		if (!cp_is_eol(cur))
		{	
			key = cur;
			cp_find_eot(cur,end);
			if (key < cur) 
			{
				*cur = 0x00;
				CP_DEBUG(" key '%s' ...", key);
				cur++;
			}
		}

		cp_skip_sep(cur,end);

		if (cp_is_comment(cur))
		{
			CP_DEBUG(" comment ...");
			cp_find_eol(cur,end);
		}

		char orig = *cur;
		if (key!=NULL && cur<end && !cp_is_eol(cur) )
		{
			val = cur;
			cp_find_eotm(cur,end);
			if (key < cur) 
			{
				while (cp_is_whitespace(cur)||cp_is_eol(cur)||cp_is_comment(cur))
				{
					cur--;
				}
				cur++;
				orig = *cur;
				*cur = 0x00;
				CP_DEBUG(" val '%s' ...", val);
				//cur++;
			}
		}

		if (key != NULL)
		{
			CP_DEBUG(" yaaaay");
			(*cb)(key,val,cbd);
			*cur = orig;
		}

		cp_find_eol(cur,end);
		cp_skip_eol(cur,end);
	}
	CP_DEBUG("\n");
	return(0);
}


