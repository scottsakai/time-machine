#include <assert.h>
#include <unistd.h>
#include <pcap.h>
#include <string>
#include <pthread.h>

#include "config.h"
#include "pcapnav/pcapnav.h"

#include "tm.h"
#include "FifoDisk.hh"
#include "Query.hh"

#include <sys/stat.h>
#include <dirent.h>
#include "util.h"

#include <limits.h>
#include <pthread.h>

/***************************************************************************
 * FifoDisk
 */


/* Query and Pkt eviction interaction 
 *
 * There is a concurrency between running queries and ongoing packet
 * eviction from FifoMem to FifoDisk. 
 *
 * a) The FifoDiskFiles std::list must not be changed while a query is 
 *    in progress, because it may corrupt the list (XXX: check this).
 *    Therefore adding or deleteing files is inhibited by chcking
 *    queryInProgress()
 * b) There is a race condition between writing/flushing evicted packets
 *    to disk and querying them. It may happen that the query thread has
 *    finished searching the most recent file in FifoDisk and is
 *    therefore going to search the FifoMem. When a packet is evicted
 *    from FifoMem during this transition period that packet will not
 *    be found be the query. 
 *    To prevent this, Fifo::query will acquire the FifoMem lock
 *    before searching the last file
 *    NOTE: It may well be, that the query thread will hold
 *    the lock for too long so that the capture thread will loose
 *    packets. A better solution must be found/.
 *
 *    These protections an be enabled/disabled at compile time. 
 *    iby Default  it is DISABLED. 
 *    See tm.h 
 */

FifoDisk::FifoDisk(const std::string& classname, uint64_t size,
				   uint64_t file_size, pcap_t* pcap_handle):
		classname(classname), size(size), file_size(file_size),
		tot_bytes(0), tot_pkts(0),
		file_number(0), pcap_handle(pcap_handle),
held_bytes(0), held_pkts(0), oldestTimestamp(0), newestTimestamp(0), queries(0) {

	pthread_mutex_init(&query_in_progress_mutex, NULL);
	
	/* load existing files */
	int filecount,i;
        struct dirent64 **flist;
	unsigned int prefixlen;
	unsigned int localfileno;
        const char *prefix;

	prefix = classname.c_str();
        prefixlen = strlen(prefix);

        filecount = scandir64("./", &flist, ScandirFileMatch, alphasort64);

        //fprintf(stderr,"Found %d files\n",filecount);

        for (i = 0; i< filecount; i++){

		struct stat64 fileinfo;

                /* can we access the file? */
                if (stat64(flist[i]->d_name, &fileinfo) != 0) continue;

                /* is it a FILE? */
                if (!S_ISREG(fileinfo.st_mode)) continue;


		/* check out the filename */
	
		/* sanity check: no way in hell we'll get a match */
        	if (strlen(flist[i]->d_name) < prefixlen)  continue;

   		/* pah. not a match */
        	if (strncmp(flist[i]->d_name, prefix, prefixlen) != 0) continue;

		/* yank out the fileno from the name */
		sscanf(flist[i]->d_name + prefixlen + 1, "%x", &localfileno);
		// fprintf(stderr,"%s: examined file number %d\n",__FUNCTION__,localfileno);
		if (localfileno > file_number) file_number = localfileno;


		/* attempt to load the file */
		files.push_back(new FifoDiskFile(flist[i]->d_name, pcap_handle));  
		/* don't use failed attempts */
		if (!files.back()->valid()){
			delete(files.back());
			files.pop_back();
		}

		/* merge stats */
		else{
			tot_bytes += files.back()->getCurFileSize();
			held_bytes += files.back()->getCurFileSize();
			tot_pkts += files.back()->getHeldPkts();
			held_pkts += files.back()->getHeldPkts();
				
			/* timestamp fun */
			if (files.back()->getOldestTimestamp() < oldestTimestamp 
			|| oldestTimestamp == 0) 
				oldestTimestamp = files.back()->getOldestTimestamp();
			if (files.back()->getNewestTimestamp() > newestTimestamp)
				 newestTimestamp = files.back()->getNewestTimestamp();
		}
						
        }

        free(flist);

	/* sort the file list */
	files.sort(FifoDiskFileCmp);

	/* open a NEW file 
	   I'm sort of caught up with the semantics of restarting TM.
	   Appending to an existing file presents all sorts of logistical
	   issues, like making pcap_nav happy, which can fail miserably.
	   Opening a new file should not fail in the same manner or frequency.
	*/
	file_number++;

	const int strsz=classname.length()+1+8+1; // "_" + "number" + "\0"
	char *new_file_name=(char*)malloc(strsz);
	snprintf(new_file_name, strsz, "%s_%08x",
	classname.c_str(), file_number);
	files.push_back(new FifoDiskFile(new_file_name, pcap_handle));
	free(new_file_name);



	/* phew! */
	//if(!files.empty()) fprintf(stderr,"%s: end ts of last file: %f, our last known ts: %f\n", __FUNCTION__, files.back()->getNewestTimestamp(),newestTimestamp);
}


FifoDisk::~FifoDisk() {
	pthread_mutex_destroy(&query_in_progress_mutex);
	while (!files.empty()) {
		delete(files.back());
		files.pop_back();
	}
}


/*
  used to compare FifoDiskFiles when sorting
 */
bool FifoDiskFileCmp( FifoDiskFile *&lhs, FifoDiskFile *&rhs){
        return lhs->getNewestTimestamp() < rhs->getNewestTimestamp();

}


void FifoDisk::addPkt(const pkt_ptr p) {
	if (size>0) {
		newestTimestamp = to_tm_time(&(((struct pcap_pkthdr*)p)->ts));
		if (files.empty() ||
				files.back()->getCurFileSize()
				+ sizeof(struct pcap_file_header)
				+ sizeof(struct pcap_pkthdr)
				+ ((struct pcap_pkthdr*)p)->caplen > file_size) {  /* Why do we have to be THAT precise?!?!? */
			// Do not add or delete files while a query is in progress, because 
			// the file iterator of the query might get fucked up. 
			// XXX: This my starve the rotation of files or generate files that
			// are way too large. Check it. 
			lockQueryInProgress();
			if (!queries) {  /* no queries in progress at the moment */
				// need new file
				if (!files.empty()) {
					// close current file which just ran full
					files.back()->close();
					if (held_bytes+file_size > size) {
						// delete oldest file
						held_bytes-=files.front()->getHeldBytes();
						held_pkts-=files.front()->getHeldPkts();
						files.front()->remove();
						delete(files.front());
						files.pop_front();
						oldestTimestamp = files.front()->getOldestTimestamp();
					}
				}
				file_number++;
				const int strsz=classname.length()+30; 
				char *new_file_name=(char*)malloc(strsz);
				snprintf(new_file_name, strsz, "%s_%.6f",
						 classname.c_str(), newestTimestamp);
				files.push_back(new FifoDiskFile(new_file_name, pcap_handle));
				free(new_file_name);
			}
			unlockQueryInProgress();
		}
		files.back()->addPkt(p);
		if (oldestTimestamp < 1e-3)
			oldestTimestamp = files.front()->getOldestTimestamp();
		held_bytes+=sizeof(struct pcap_pkthdr)+((struct pcap_pkthdr*)p)->caplen;
		held_pkts++;
		tot_bytes+=sizeof(struct pcap_pkthdr)+((struct pcap_pkthdr*)p)->caplen;
		tot_pkts++;
	}
}

tm_time_t FifoDisk::getOldestTimestamp() const {
	return oldestTimestamp;
}
tm_time_t FifoDisk::getNewestTimestamp() const {
	return newestTimestamp;
}

/*
uint64_t FifoDisk::query(QueryRequest *qreq, QueryResult *qres,
					 IntervalSet *interval_set) {
	FifoDiskFile *cur_file;
	uint64_t matches=0;
	IntervalSet::iterator i_i=interval_set->begin();
	std::list <FifoDiskFile*>::iterator f_i=files.begin();
	while ( f_i!=files.end() && i_i != interval_set->end() ) {
		cur_file = *f_i;
		f_i++;
		if (f_i == files.end()) {
			lockLastFile();
		}
		matches += cur_file->query(interval_set, qreq, qres);
	}
	return matches;
}
*/


/***************************************************************************
 * FifoDiskFile
 */

FifoDiskFile::FifoDiskFile(const std::string& filename, pcap_t* pcap_handle, int flags):
		filename(filename), is_open(false), is_valid(true), 
		is_dirty(false), exit_writer(false), cur_file_size(0), held_bytes(0), held_pkts(0),
		pcap_handle(pcap_handle), oldest_timestamp(0), 
		newest_timestamp(0) {

	// mutexes to protect multithreaded access
	pthread_mutex_init(&metadata_lock_mutex, NULL);
	pthread_mutex_init(&queue_lock_mutex, NULL);
	pthread_mutex_init(&write_cond_lock_mutex, NULL);

	// used to signal writer thread when there's work
	pthread_cond_init(&write_cond, NULL);


	// take a guess at the pcap packet header size (might be different than what gets written to disk)
	pkt_hdr_size = sizeof(struct pcap_pkthdr);

	/* check the flags -- might want to just truncate and open */
	if(flags & FIFO_DISK_FILE_ENAB_TRUNC){
		open();
		return;
	}

	loadState();
	if (is_valid) return;

	/* otherwise, must be a new file. */
	open();
	is_valid=true;
}


void FifoDiskFile::open() {
	pcap_dumper_handle=pcap_dump_open(pcap_handle, filename.c_str());
	if (!pcap_dumper_handle) {
		char *pcap_errstr = pcap_geterr(pcap_handle);
		tmlog(TM_LOG_ERROR, "storage", "could not open file %s: %s",
				filename.c_str(), pcap_errstr);

		fprintf(stderr, "could not open file %s: %s",
				filename.c_str(), pcap_errstr);
	} else {
		is_open=true;
		is_dirty=true;
		cur_file_size += sizeof(struct pcap_file_header);

		// fire off the writer thread
		pthread_create(&writer_thread, NULL, &writerMain, this);

	}
}

/* Load state from a .summary file 
* Note: only call this from loadState()
*/
void FifoDiskFile::loadStateFromSummary() {
	char summary_fn[PATH_MAX];
	FILE * fp;

	// figure out the summary file name
	memset(summary_fn, 0, PATH_MAX);
	snprintf(summary_fn, PATH_MAX, "%s.summary", filename.c_str());

	// open the summary file and parse it
	fp = fopen(summary_fn, "r");
	if (fp == NULL) {
		return;
	}

	fscanf(fp,"file_size:%ld\nheld_pkts:%lu\nheld_bytes:%lu\noldest_timestamp:%lf\nnewest_timestamp:%lf", &cur_file_size, &held_pkts, &held_bytes, &oldest_timestamp, &newest_timestamp);

	fclose(fp);

	return;
}

/* Load state from the pcap file (slow!) 
* Note: only call this from loadState()
*/
void FifoDiskFile::loadStateFromPcap() {
	struct stat64 fileinfo;
	struct bpf_timeval start_tv, end_tv;
	pcapnav_t *pn;
	int statRet;
	
	statRet = stat64(filename.c_str(),&fileinfo);
	if (statRet == 0) {
		cur_file_size = fileinfo.st_size;
	}

	if (cur_file_size < 1) {
		is_valid = false;
		return;
	}

	// open it with pcapnav 
	pcapnav_init();
	pn = pcapnav_open_offline(filename.c_str());
	if (pn == NULL) {
		is_valid = false;
		return;
	}

	// get the time range
	if (pcapnav_get_timespan(pn,&start_tv,&end_tv) != 0) {
		fprintf(stderr,"%s: %s might not be a valid pcap file.\n",
		__FUNCTION__,filename.c_str());
		is_valid = false;
		pcapnav_close(pn);
		return;
	}

	// update our time range. 
	newest_timestamp = to_tm_time(&end_tv);
	oldest_timestamp = to_tm_time(&start_tv);

	// for very tiny files, sometimes the newest_timestamp < oldest_timestamp
	if (newest_timestamp < oldest_timestamp) {
		newest_timestamp = oldest_timestamp;
	}

	// number of bytes in trace 
	held_bytes = pcapnav_get_size(pn);

	// number of packets in trace 
	held_pkts = 0;
	while (pcapnav_next(pn,NULL) != NULL) held_pkts++;
 	
	// I think we're done with pcapnav 
	pcapnav_close(pn);


	// done. 
	fprintf(stderr,"%s: loaded file %s: %llu packets, %llu bytes, "
		"%llu size, from %f to %f\n",
	__FUNCTION__,
	filename.c_str(),
	(unsigned long long)held_pkts,
	(unsigned long long)held_bytes,
	(unsigned long long)cur_file_size,
	oldest_timestamp,
	newest_timestamp);

	is_dirty = true;
	return;
}

/* Load state from summary file if present and valid, otherwise
* derive state from pcap file
*/
void FifoDiskFile::loadState() {
	struct stat64 fileinfo;
	int64_t pcap_file_size = 0;
	int rv;

	// we'll sanity check in a bit...
	is_valid = false; 

	// get pcap file size
	rv = stat64(filename.c_str(), &fileinfo);
	if( rv != 0 )
	{
		//perror("Stat: ");
		return;
	}
	pcap_file_size = fileinfo.st_size;

	// try loading from summary file
        loadStateFromSummary();

	// fprintf(stderr,"%s loaded from summary:\n fsz:%ld\n hpk:%lu\n hby:%lu\n old:%0.6f\n new:%0.6f\n", __FUNCTION__, cur_file_size, held_pkts, held_bytes, oldest_timestamp, newest_timestamp);

	// here's the sanity check.
	if (cur_file_size == pcap_file_size && 
		held_pkts < LONG_MAX && 
		held_bytes < LONG_MAX && 
		oldest_timestamp >= 0.0l && 
		newest_timestamp >= 0.0l && 
		oldest_timestamp <= newest_timestamp) {

		is_valid = true;
		return;
	}

	// load from pcap file
	is_valid = true; // the call below will set to false if there's trouble
	loadStateFromPcap();

	return;
}

FifoDiskFile::~FifoDiskFile() {
	if (is_open) close();

	// done with the mutexes
	pthread_mutex_destroy(&metadata_lock_mutex);
	pthread_mutex_destroy(&queue_lock_mutex);
	pthread_mutex_destroy(&write_cond_lock_mutex);
	pthread_cond_destroy(&write_cond);



}

void FifoDiskFile::remove() {
	if (is_open) close();
	unlink(filename.c_str());

	// unlink the summary file
	char summary_fn[PATH_MAX];

	// figure out the summary file name
	memset(summary_fn, 0, PATH_MAX);
	snprintf(summary_fn, PATH_MAX, "%s.summary", filename.c_str());

	unlink(summary_fn);
}

void FifoDiskFile::writeSummaryFile(){
	char summary_fn[PATH_MAX];
	FILE * fp;

	// figure out the summary file name
	memset(summary_fn, 0, PATH_MAX);
	snprintf(summary_fn, PATH_MAX, "%s.summary", filename.c_str());

	// write out the summary file
	fp = fopen(summary_fn, "w");
        if ( fp == NULL )
        {
		perror("Unable to open .summary file for writing: ");
		return;
        }
        fprintf(fp,"file_size:%ld\nheld_pkts:%lu\nheld_bytes:%lu\noldest_timestamp:%0.8f\nnewest_timestamp:%0.8f", cur_file_size, held_pkts, held_bytes, oldest_timestamp, newest_timestamp);
        fclose(fp);

	is_dirty = false;
}


void FifoDiskFile::close() {
	// shut down the writer thread
	tmlog(TM_LOG_DEBUG, "FifoDiskFile", "%s shutting down writer thread", filename.c_str());
	lockMetadata();
	exit_writer = true;
	unlockMetadata();
	pthread_mutex_lock(&write_cond_lock_mutex);
	pthread_cond_signal(&write_cond);
	pthread_mutex_unlock(&write_cond_lock_mutex);
	tmlog(TM_LOG_DEBUG, "FifoDiskFile", "%s waiting for writer to exit", filename.c_str());
	pthread_join(writer_thread,NULL);
	tmlog(TM_LOG_DEBUG, "FifoDiskFile", "%s writer exited.", filename.c_str());

	// clean out the queue
	while (!writeQueue.empty()) {
		pkt_ptr p;
		tmlog(TM_LOG_DEBUG, "FifoDiskFile", "%s writing remainder of queue", filename.c_str());

		// pull a packet off the queue
		p = writeQueue.front();
		writeQueue.pop();
		if (p != NULL) {
			writePkt((struct pcap_pkthdr*)p, (unsigned char*)p + sizeof(struct pcap_pkthdr));
			free(p);
		}
	}

	pcap_dump_close(pcap_dumper_handle);
	is_open=false;
	writeSummaryFile();
}

// writePkt actually writes the packet to disk.
// This function WILL block on IO, so don't call it from the capture thread.
void FifoDiskFile::writePkt(const struct pcap_pkthdr *header,
						  const unsigned char *packet) {
	long prev = 0;

	assert(is_open==true);

	// pcap_dump can write more or less bytes than just sizeof(pcap_pkthdr) + caplen. figure out what the header size is!
	// lock here - held_pkts
	if (getHeldPkts()==0){
		prev = pcap_dump_ftell(pcap_dumper_handle);
	}

	pcap_dump((u_char*)pcap_dumper_handle,
			  header,                         // pcap header
			  packet);                        // packet

	// okay to hold a lock here, as it'll execute fast
	lockMetadata();
	if (held_pkts==0){
		oldest_timestamp=to_tm_time(&header->ts);
		pkt_hdr_size = pcap_dump_ftell(pcap_dumper_handle) - prev - header->caplen;
	}
	else newest_timestamp=to_tm_time(&header->ts);

	held_pkts++;
	held_bytes+=pkt_hdr_size+header->caplen;
	cur_file_size += pkt_hdr_size+header->caplen;
	unlockMetadata();
}	

// When addPkt gets called, the caller assumes that we will "add the packet" and
// not drop it on the floor.  We'll have to queue the packet internally so
// the writer thread can write it to disk.  Meanwhile, the queue can grow
// to insane sizes due to transient IO contention.
// To make matters worse, we need to copy p, as the caller will want the
// memory back as soon as we're done here.
// Since we've got plenty of CPU and not so much disk, first try a naive 
// malloc/memcpy/free for each packet.
void FifoDiskFile::addPkt(pkt_ptr p) {
	
	pkt_ptr pkt_local = NULL;
	uint32_t pkt_size = 0;
	
	// figure out how big p is
	pkt_size = sizeof(struct pcap_pkthdr) + ((struct pcap_pkthdr*)p)->caplen;

	// need to make a copy of p
	pkt_local = (pkt_ptr)malloc(pkt_size);
	memcpy(pkt_local, p, pkt_size);

	// shove it in the write queue
	lockQueue();
	writeQueue.push(pkt_local);
	unlockQueue();

	// signal the writer thread
	pthread_mutex_lock(&write_cond_lock_mutex);
	pthread_cond_signal(&write_cond);
	pthread_mutex_unlock(&write_cond_lock_mutex);

	//faddPkt((struct pcap_pkthdr*)p,         // pcap header
	//	   p+sizeof(struct pcap_pkthdr));  // packet
}

uint64_t FifoDiskFile::query( QueryRequest *qreq, QueryResult *qres, IntervalSet *set) {
	uint64_t matches = 0;
	uint64_t scanned_packets=0;
	ConnectionID4 *c_id;
	struct timeval tv1, tv2;
	struct timeval tv;
	int res;
	int intcnt=0;
	int first_pkt_for_this_int;

	// FIXME: Protect the pcap_dumper_handle from capture thread!!
	if (is_open)
		flush();

	pcapnav_t *ph=pcapnav_open_offline(filename.c_str());
	if (!ph) {
		char *pcap_errstr = pcapnav_geterr(ph);
		tmlog(TM_LOG_ERROR, "query", "%d FifoDiskFile::query: could not open file %s: %s",
				qres->getQueryID(), filename.c_str(), pcap_errstr);
	} else {
		struct pcap_pkthdr hdr;
		const u_char *pkt;

		if (pcapnav_get_timespan(ph, &tv1, &tv2) != 0) {
			tmlog(TM_LOG_WARN, "query",  "%d pcapnav could not obtain timespan.",
					qres->getQueryID());
			  /* Rest of error handling */
		}
		tmlog(TM_LOG_DEBUG, "query", "%d FifoDiskFile::query: opened file %s. timespan is [%lf,%lf]",
				qres->getQueryID(), filename.c_str(), to_tm_time(&tv1), to_tm_time(&tv2));

		for (IntervalSet::iterator it=set->begin(); it!=set->end(); it++) {
			// FIXME: get rid of this assert
			assert(getNewestTimestamp() >= getOldestTimestamp());
			/* XXX: this should be handled by pcapnav_goto_timestamp.... 
			if (getOldestTimestamp() > (*it).getLast() ||
					getNewestTimestamp() < (*it).getStart() ) {
				fprintf(stderr, "Nicht im File: [%lf, %lf] <> [%lf,%lf]\n", 
						getOldestTimestamp(), getNewestTimestamp(), 
						(*it).getStart(), (*it).getLast());
				continue;
			}
			*/
			tmlog(TM_LOG_DEBUG, "query", "%d FifoDiskFile: New Int %i of %i: [%lf, %lf]", intcnt, set->getNumIntervals(),
					qres->getQueryID(), it->getStart(), it->getLast());
			
			tv.tv_sec=(int)(*it).getStart();
			tv.tv_usec=(int)(1000000*((*it).getStart()-tv.tv_sec));
			
			// Check if interval overlaps trace start
			// FIXME: Don't hardcode the security margin with 1ms!!
			if ( (*it).getLast()+1e-3 >= to_tm_time(&tv1) &&
					(*it).getStart() <= to_tm_time(&tv1)) {
				res = PCAPNAV_DEFINITELY;
				pcapnav_goto_offset(ph, 0, PCAPNAV_CMP_LEQ);
				tmlog(TM_LOG_DEBUG, "query", "%d Interval overlapped trace start. Goto 0",
						qres->getQueryID());
			}
			else 
				res = pcapnav_goto_timestamp(ph, &tv);
			switch(res) {
				case PCAPNAV_ERROR:
					tmlog(TM_LOG_ERROR, "query", " %d pcapnav_goto_timestamp ERROR", qres->getQueryID()); 
					break;
				case PCAPNAV_NONE:
					tmlog(TM_LOG_DEBUG, "query", "%d pcapnav_goto_timestamp NONE", qres->getQueryID()); 
					break;
				case PCAPNAV_CLASH:
					tmlog(TM_LOG_ERROR, "query", "%d pcapnav_goto_timestamp CLASH", qres->getQueryID()); 
					break;
				case PCAPNAV_PERHAPS:
					tmlog(TM_LOG_ERROR, "query", "%d pcapnav_goto_timestamp PERHAPS", qres->getQueryID()); 
					break;
				default:
					break;
			}
			if (res != PCAPNAV_DEFINITELY) {
				continue;
			}
			first_pkt_for_this_int = 1;
			do {
				pkt = pcapnav_next(ph, &hdr);
				scanned_packets++;
				if (!pkt)
					break;
				tm_time_t t=to_tm_time(&hdr.ts);
				if (first_pkt_for_this_int) {
					tmlog(TM_LOG_DEBUG, "query", "First packet ts for this int: %lf", t);
					first_pkt_for_this_int=0;
				}
				if (t>(*it).getLast())
					break;
				if (t>qreq->getT1())
					break;
				if (t<qreq->getT0())
					continue;
				if (qreq->matchPkt(&hdr, pkt))  {
					matches++;
					qres->sendPkt(&hdr, pkt);
					if (qreq->isSubscribe()) {
						c_id = new ConnectionID4(pkt);
						storage->getConns().subscribe(c_id, qres);
						delete c_id;
					}
				}
			} while (pkt);
		}
	}
	//DEBUG
	tmlog(TM_LOG_DEBUG, "query", "%d FifoDiskFile::query [HAVE_LIBPCAPNAV] finished; matches %" PRIu64 "; examined %" PRId64, 
			qres->getQueryID(), (unsigned)matches, scanned_packets);

	pcapnav_close(ph);
	return matches;
}


bool FifoDiskFile::operator<(FifoDiskFile* rhs){
	return newest_timestamp < rhs->getNewestTimestamp();
}
	

// This will just run in a loop until shut down by
// setting done = false
// we'll block on a cv so as to not burn up the cpu
void * writerMain(void * arg){
	while (((FifoDiskFile*)arg)->flushQueue() == false);
	return 0;
}

// called by writerMain, since threads run static functions.
// returns true if writerMain should exit.
bool FifoDiskFile::flushQueue() {
	bool done_local = false;
	bool empty = false;
	pkt_ptr p = NULL;

	// wait on cv
	pthread_mutex_lock(&write_cond_lock_mutex);
	pthread_cond_wait(&write_cond, &write_cond_lock_mutex);
	pthread_mutex_unlock(&write_cond_lock_mutex);

	//tmlog(TM_LOG_DEBUG, "FifoDiskFile", "%s woken up to write!", filename.c_str());

	// write to disk
	while (true) {
		lockQueue();
		// stop if nothing to do
		if ( writeQueue.empty() ) {
			unlockQueue();
			break;
		}

		// pull a packet off the queue
		p = writeQueue.front();
		writeQueue.pop();
		unlockQueue();

		// write it to disk
		if (p != NULL) {
			writePkt((struct pcap_pkthdr*)p, (unsigned char*)p + sizeof(struct pcap_pkthdr));
			free(p);
		}
	}

	// find out if we're done
	lockMetadata();
	done_local = exit_writer;
	unlockMetadata();
	
	return done_local;
}

