#include "util.h"
 
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>

/* 
   used in scandir - return 1 and let someone else figure out if the file
   is appropriate.
 */
int ScandirFileMatch(const struct dirent64* a){
	const char * dot;

	// skip files ending in ".summary"
	dot = strrchr(a->d_name, '.');
	if ( dot && dot == strstr(dot,".summary") ) return 0;
	
	return 1;
}
