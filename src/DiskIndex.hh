#ifndef INDEXFILE_HH
#define INDEXFILE_HH

#include <netinet/in.h>  // ntohl()
#include <fstream>
#include <list>
#include <set>
#include <pcap.h>
#include <sstream>
#include <pthread.h>

#include "types.h"
#include "IndexField.hh"
#include "IndexEntry.hh"
#include "IndexHash.hh"
#include "sqlite3/sqlite3.h"


/* forward declaration */
class Storage;

/*
 * Organisation on Disk: 
 * The index maintainer threads writes in regular intervals (on every rotate)
 * the index entries to file. This file is an sqlite3 database.  Sqlite3 will
 * take care of all of the i/o and storage nuances.
 *
 * 
 ***************************************************************************
 * Note on threading. 
 *
 * The index maintaining thread calls writeIndex() to create a new index file
 * The aggregation thread call aggregate() to aggregate/merge files together.
 * Query threads call lookup to search for entries on disk. 
 *
 *   file_number[] and file_number_oldest[] are accessed from multiple threads as follows:
 *   writeIndex() reads and updates file_number[0]. The lock is aquired, file_number[0] is read, 
 *       the lock is released, the file is written (with the just read file_number), the lock
 *       is aquired, file_number[0] is incremented, the lock is released. Since only  writeIndex
 *       updates file_number[0] it is save to release the lock between reading and incrementing. 
 *       While writeIndex is in progress, other threads just won't see the file that is just 
 *       written.
 *       Since the IndexEntrys are kept in memory, until file_number[0] is updated, no race 
 *       condition occurs in which we might temporaliy "loose" some entries. 
 *       AS LONG AS THE MEMORY IS QURIED BEFORE THE DISK INDEX IS QUERIED.
 *   aggregate_internal(), reads all file_numbers and file_number_oldest entries, it updates all
 *       entries except file_number[0].  The same mechanism's as for writeIndex also apply here: 
 *       first reading the file_number, file_number_oldest  vars, then aggregating and creating 
 *       new files (without holding the lock), then updating the file_number, file_number_oldest
 *       entries. _After_ the file_number_oldest vars have been updated, the files that have just
 *       been aggregated can be unlink()ed savely without holding the lock.
 *   lookup() reads file_number and file_number_oldest. It will hold the lock during the whole
 *       lookup procedure. This ensures that no file is unlink()ed that is currently read
 *       (or that is going to be read) by an ongoing lookup.
 *       FIXME: this is inefficient and should be changed.
 *
 *
 */


/***************************************************************************
 * class DiskIndex
 */

class DiskIndex {
public:
	DiskIndex() {};
	virtual void lookup(IntervalSet *iset, IndexField *key, tm_time_t t0, tm_time_t t1) = 0;
	virtual void writeIndex( IndexHash *ih) = 0;
	virtual ~DiskIndex() {}
};

template <class T> class IndexFiles: DiskIndex {
public:
	IndexFiles(const std::string& pathname, const std::string& indexname);
	~IndexFiles();
	void lookup(IntervalSet *iset, IndexField *key, tm_time_t t0, tm_time_t t1);
	void writeIndex(IndexHash *ih);
	bool inTransaction() { return in_transaction; }
	bool isValid() { return valid; }
protected:
	std::string indexname;
	std::string pathname;
	bool valid;
	sqlite3* db;
	sqlite3_stmt* stmt;
	bool in_transaction;
};



#include "DiskIndex.cc"


#endif
