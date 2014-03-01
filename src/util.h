#ifndef UTIL_H
#define UTIL_H
 
#include "types.h"
#include <sys/stat.h>
#include <dirent.h>

// has moved to types.h
// extern tm_time_t to_tm_time(const struct timeval* tv);
 
int ScandirFileMatch(const struct dirent64* a);

#endif
