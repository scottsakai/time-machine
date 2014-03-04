#ifndef INDEXFILE_CC
#define INDEXFILE_CC

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>  // htonl()
#include <errno.h>

#include <fstream>
#include <vector>

#include "tm.h"
#include "types.h"
#include "packet_headers.h"
#include "Storage.hh"
#include "Query.hh"
#include "IndexHash.hh"
#include "conf.h"
#include <unistd.h>
#include <time.h>

#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include "util.h"
#include <regex.h>


// use epsilon to enlarge time range by "just a little"
#define EPS 1e-3



/***************************************************************************
 * class IndexFiles<T>
 */

template <class T>
IndexFiles<T>::IndexFiles(const std::string& pathname, const std::string& indexname):
		indexname(indexname),
		pathname(pathname),
		valid(false),
		db(NULL),
		stmt(NULL),
		in_transaction(false),
		entries(0),
		earliest(ULLONG_MAX),
		latest(0)
{
	
	/* dig up the existing current file */
	if (loadCurrentFile() != true) {
		return;
	}

	/* done. */
	valid = true;
	return;
}



template <class T>
IndexFiles<T>::~IndexFiles() {
	closeCurrentFile();
}


/* Load or create a new sqlite database file.
 * If an existing current file is present, load it.
 * To create an empty current database, move the existing one first!
 * Returns true on success, false on failure
 */
template <class T>
bool IndexFiles<T>::loadCurrentFile() {
  	sqlite3_stmt* qstmt = NULL;
	int rc;

	/* close the current file if open */
	if (db != NULL) {
		closeCurrentFile();
	}

	/* reset counters */
	entries = 0;

	/* we're going to stash everything in one sqlite file per indexname */
	char index_fn[PATH_MAX];
	memset(index_fn, 0, PATH_MAX);
	snprintf(index_fn, PATH_MAX, "%s/%s-current.sqlite", pathname.c_str(), indexname.c_str());

	/* open db */
	if (sqlite3_open_v2(index_fn, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not open sqlite file %s: %s", index_fn, sqlite3_errmsg(db));
		return false;
	}

	/* set some pragmas. they can silently fail and the DB will still work */
	sqlite3_exec(db, "PRAGMA synchronous = OFF;", NULL, NULL, NULL); // quick but dangerous. don't crash the host.
	sqlite3_exec(db, "PRAGMA automatic_index = false;", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA mmap_size = 1073741824;", NULL, NULL, NULL);

	/* create the table if it doesn't exist. */
	rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS tm_index (k BLOB, start INT, end INT);", NULL, NULL, NULL);
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not create sqlite table in file %s: %s", index_fn, sqlite3_errmsg(db));
		return false;
	}


	/* create indexes on the table if they don't exist. */
	// most searches will be against 'k'
	rc = sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS index_tm_index_k ON tm_index(k)", NULL, NULL, NULL);
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not create sqlite index on k in file %s: %s", index_fn, sqlite3_errmsg(db));
		return false;
	}


	// do some deduplication
	rc = sqlite3_exec(db, "CREATE TRIGGER IF NOT EXISTS tm_insert_dedup BEFORE INSERT ON tm_index "
		" for each row when (select k from tm_index where k = NEW.k and start = NEW.start) IS NOT NULL "
		" BEGIN "
	        "  update tm_index set "
		"    end = NEW.end "
		"    where "
		"      k = NEW.k AND "
		"      start = NEW.start AND "
		"      end < NEW.end; "
		"  select raise(ignore); "
		" END; ", NULL, NULL, NULL);
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not create sqlite trigger in file %s: %s", index_fn, sqlite3_errmsg(db));
		return false;
	}


	/* pull stats */
	tmlog(TM_LOG_NOTE, indexname.c_str(), "Querying stats for tm_index in file: %s", index_fn);

	rc = sqlite3_prepare_v2(db,
		"SELECT count(*), min(start), max(end) from tm_index;",
		-1, &qstmt, NULL);
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not prepare stats query for table tm_index in file: %s %s", index_fn, sqlite3_errmsg(db));
		return false;
	}
	// db should not be locked yet. it's either new or we're called from
	// the constructor at startup
	rc = sqlite3_step(qstmt);
	if (rc != SQLITE_ROW) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not execute stats query for table tm_index in file: %s %s", index_fn, sqlite3_errmsg(db));
		return false;
	}
	entries = sqlite3_column_int64(qstmt, 0);
	earliest = sqlite3_column_int64(qstmt, 1);
	latest = sqlite3_column_int64(qstmt, 2);
	rc = sqlite3_finalize(qstmt);
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not finalize stats query for table tm_index in file %s %s", index_fn, sqlite3_errmsg(db));
		return false;
	}
	tmlog(TM_LOG_NOTE, indexname.c_str(), "Loaded stats from file: %s - entries %llu, earliest %llu, latest %llu", index_fn, entries, earliest, latest);


	/* all done! */
	return true;
}


/* Close the current sqlite database file */
template <class T>
void IndexFiles<T>::closeCurrentFile() {
	/* close db */
	if (stmt) {
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	if (in_transaction) {
		sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
		in_transaction = false;
	}
	if (db) {
		sqlite3_close(db);
		db = NULL;
	}
}


/* Rotate (out) the current sqlite database file and bring in a new one */
template <class T>
void IndexFiles<T>::rotateCurrentFile() {
	int rc = 0;

	// identify src (current) and dst (archived) filenames
	char index_fn_src[PATH_MAX];
	char index_fn_dst[PATH_MAX];
	memset(index_fn_src, 0, PATH_MAX);
	memset(index_fn_dst, 0, PATH_MAX);

	closeCurrentFile();

	snprintf(index_fn_src, PATH_MAX, "%s/%s-current.sqlite", pathname.c_str(), indexname.c_str());

	snprintf(index_fn_dst, PATH_MAX, "%s/%s-archived-%llu-%llu.sqlite", pathname.c_str(), indexname.c_str(), (long long unsigned int)earliest, (long long unsigned int)latest);

	rc = rename(index_fn_src, index_fn_dst);
	if (rc != 0) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "Unable to rename %s to %s: %s", index_fn_src, index_fn_dst, strerror(errno));
	}

	// make sure db points to something useful
	loadCurrentFile();
}


/* 
    Examine indicies between t0 and t1 for start/end entries associated with key.
    Place results in iset.
*/
template <class T>
void IndexFiles<T>::lookup(IntervalSet *iset, IndexField *key, tm_time_t t0, tm_time_t t1) {
	char index_fn[PATH_MAX];
	char filter[PATH_MAX];
	char scan_template[PATH_MAX];
	regex_t re_filter;
	int filecount, i, rc;
	long long unsigned int f_start, f_end;
	struct dirent64 **flist;

	/* We'll need to use a regex to filter files */
	memset(filter, 0, PATH_MAX);
	snprintf(filter, PATH_MAX, "^%s/%s-archived-[[:digit:]][[:digit:]]*-[[:digit:]][[:digit:]]*\\.sqlite$", pathname.c_str(), indexname.c_str());
	rc =  regcomp(&re_filter, filter, 0);
	if (rc != 0) {
	    tmlog(TM_LOG_ERROR, "lookup", "Could not compile file filter regex");
	    return;
	}

	/* template for sscanf */
	memset(scan_template, 0, PATH_MAX);
	snprintf(scan_template, PATH_MAX, "%s-archived-%%llu-%%llu", indexname.c_str());

	/* Start with the current disk index */
	memset(index_fn, 0, PATH_MAX);
	snprintf(index_fn, PATH_MAX, "%s/%s-current.sqlite", pathname.c_str(), indexname.c_str());
	lookupFile(index_fn, iset, key, t0, t1);

	/* Now go through all candidate archive files */
	filecount = scandir64(pathname.c_str(), &flist, ScandirFileMatch, alphasort64);
	for (i = 0; i < filecount; i++) {
		struct stat64 fileinfo;

		snprintf(index_fn, PATH_MAX, "%s/%s", pathname.c_str(), flist[i]->d_name);

		/* simple sanity checks */
		// access?
		if (stat64(index_fn, &fileinfo) != 0) continue;
		// regular file?
		if (!S_ISREG(fileinfo.st_mode)) continue;

		// matches filter?
		if (regexec(&re_filter, index_fn, 0, NULL, 0) != 0) continue;

		/* get time range from file name (note: use bare name here) */
		rc = sscanf(flist[i]->d_name, scan_template, &f_start, &f_end);
		if (rc != 2) continue;

		/* skip files outside range */
		if (f_start > t1 || f_end < t0) continue;

		/* do the lookup */
		lookupFile(index_fn, iset, key, t0, t1);
	}

	// done!
 	regfree(&re_filter);
	return;
}


/*
    Examine index_fn between t0 and t1 for start/end entries associated with key.
    Place results in iset.
    Called by lookup()
*/
template <class T>
void IndexFiles<T>::lookupFile(char* index_fn, IntervalSet *iset, IndexField *key, tm_time_t t0, tm_time_t t1) {
	sqlite3* qdb = NULL;
	sqlite3_stmt* qstmt = NULL;
	int rc = 0;

	/* since this may run in a different thread, use a separate database connection */

	/* open database */
	rc = sqlite3_open_v2(index_fn, &qdb, SQLITE_OPEN_READONLY, NULL);
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "[lookup] Could not open sqlite file %s: %s", index_fn, sqlite3_errmsg(qdb));
		return;
	}

	/* set some pragmas. they can silently fail and the DB will still work */
	sqlite3_exec(qdb, "PRAGMA synchronous = OFF;", NULL, NULL, NULL); // quick but dangerous. don't crash the host.
	sqlite3_exec(qdb, "PRAGMA automatic_index = false;", NULL, NULL, NULL);
	sqlite3_exec(qdb, "PRAGMA mmap_size = 1073741824;", NULL, NULL, NULL);

	/* prepare statement */
	rc = sqlite3_prepare_v2(qdb,
		"SELECT start, end from tm_index where k = ? AND end >= ? AND start <= ?;",
		-1, &qstmt, NULL);
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "[lookup] Could not prepare query: %s", sqlite3_errmsg(qdb));
		sqlite3_close(qdb);
		return;
	}

	/* bind values */
	rc = sqlite3_reset(qstmt);
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "[lookup] Could not reset statement: %s", sqlite3_errmsg(qdb));
		sqlite3_finalize(qstmt);
		sqlite3_close(qdb);
		return;
	}

	rc = sqlite3_bind_blob(qstmt, 1, key->getConstKeyPtr(), key->getKeySize(), SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "[lookup] Could not bind key value: %s", sqlite3_errmsg(qdb));
		sqlite3_finalize(qstmt);
		sqlite3_close(qdb);
		return;
	}

	rc = sqlite3_bind_double(qstmt, 2, t0 - EPS);
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "[lookup] Could not bind t0 value: %s", sqlite3_errmsg(qdb));
		sqlite3_finalize(qstmt);
		sqlite3_close(qdb);
		return;
	}

	rc = sqlite3_bind_double(qstmt, 3, t1 + EPS);
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "[lookup] Could not bind t1 value: %s", sqlite3_errmsg(qdb));
		sqlite3_finalize(qstmt);
		sqlite3_close(qdb);
		return;
	}


	while (1) {
		/* try to execute query */
		int tries;
		rc = SQLITE_DONE;
		for (tries = 10; tries > 0; tries--) {
			rc = sqlite3_step(qstmt);
			if (rc == SQLITE_ROW || rc == SQLITE_DONE) {
				break;
			}
			usleep(210000); // not a multiple of the other usleep() call
		}
				
		/* stop if no rows */
		if (rc != SQLITE_ROW) {
			break;
		}

		Interval iv = Interval(sqlite3_column_double(qstmt, 0), sqlite3_column_double(qstmt, 1));
		tmlog(TM_LOG_DEBUG, "query", "IFR::lookupEntry: adding interval [%lf,%lf]",
		                                iv.getStart(), iv.getLast());
		iset->add(iv);
	}

	rc = sqlite3_finalize(qstmt);
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "[lookup] Could not finalize statement: %s", sqlite3_errmsg(qdb));
		sqlite3_close(qdb);
		return;
	}

	sqlite3_close(qdb);
	return;
}


template <class T>
void IndexFiles<T>::writeIndex(IndexHash *ih) {
	IndexEntry *ie;
	const Interval *ci;
	int rc;
	uint64_t start = 0;
	uint64_t last = 0;
	uint32_t keysize = 0;
	uint32_t count = 0;

	/* start the iterator */
	ih->initWalk();
	ie = ih->getNextDelete();

	/* stop here if nothing to do */
	if (ie == NULL) {
		ih->clear();
		return;
	}

	/* get key size */
	keysize = ie->getKey()->getKeySize();

	/* prepare to insert */
	rc = sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not begin sql transaction: %s", sqlite3_errmsg(db));
		// don't clear ih, in case error is transient
		return;
	}
	in_transaction = true;

	rc = sqlite3_prepare_v2(db,
		"INSERT into tm_index (k, start, end) values(?,?,?);",
		-1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not prepare sql: %s", sqlite3_errmsg(db));
		sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
		in_transaction = false;
		// don't clear ih, in case error is transient
		return;
	}
	
	
	/* insert index entries */
	while(ie)  {
		count++;
		ci = ie->getIntList();
		//keysize = ie->getKey()->getKeySize();
		//fprintf(stderr, "%08X:%d - %08X:%d\n", tmp->ip1, tmp->port1, tmp->ip2, tmp->port2);
		// using do ... while is safe, since getIntList will always return a valid
		// pointer
		do {
			rc = sqlite3_reset(stmt);
			if (rc != SQLITE_OK) {
				tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not reset stmt handle: %s", sqlite3_errmsg(db));
				sqlite3_finalize(stmt);
				stmt = NULL;
				sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
				in_transaction = false;
				return;
			}

			/* bind values */
			rc = sqlite3_bind_blob(stmt, 1, ie->getKey()->getConstKeyPtr(), keysize, SQLITE_STATIC);
			if (rc != SQLITE_OK) {
				tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not bind key value: %s", sqlite3_errmsg(db));
				sqlite3_finalize(stmt);
				stmt = NULL;
				sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
				in_transaction = false;
				return;
			}

			start = (((int64_t)(*ci).getStart()) / 60) * 60;
			if (start < earliest || earliest == 0) earliest = start;
			rc = sqlite3_bind_int64(stmt, 2, start);
			if (rc != SQLITE_OK) {
				tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not bind start value: %s", sqlite3_errmsg(db));
				sqlite3_finalize(stmt);
				stmt = NULL;
				sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
				in_transaction = false;
				return;
			}

			last = ((((int64_t)(*ci).getLast()) / 60) + 1) * 60;
			if (last > latest) latest = last;
			rc = sqlite3_bind_int64(stmt, 3, last);;
			if (rc != SQLITE_OK) {
				tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not bind end value: %s", sqlite3_errmsg(db));
				sqlite3_finalize(stmt);
				stmt = NULL;
				sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
				in_transaction = false;
				return;
			}

			/* do the deed */
			rc = sqlite3_step(stmt);
			if (rc != SQLITE_DONE) {
				tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not execute statement: %s", sqlite3_errmsg(db));
				sqlite3_finalize(stmt);
				stmt = NULL;
				sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
				in_transaction = false;
				return;
			}

			ci = ci->getNextPtr();
		} while(ci);
		ie=ih->getNextDelete();
	}


	/* done inserting */
	rc = sqlite3_finalize(stmt);
	stmt = NULL;
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not finalize statement: %s", sqlite3_errmsg(db));
		sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
		in_transaction = false;
		return;
	}
	
	/* sometimes the db is locked from a query thead. try again a few times */
	int tries;
	for (tries = 1000; tries > 0; --tries) {
		rc = sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, NULL);
		if (rc == SQLITE_OK || rc != SQLITE_BUSY) {
			break;
		}
		usleep(100000);
	}
	if (rc != SQLITE_OK) {
		tmlog(TM_LOG_ERROR, indexname.c_str(), "Could not commit transaction: %s", sqlite3_errmsg(db));
		sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
		in_transaction = false;
		return;
	}

	entries += count;

	/* rotate out if too many entries */
	if (entries > IDX_MAX_ENTRIES) rotateCurrentFile();
}

/** No need to aggregate */





#endif
