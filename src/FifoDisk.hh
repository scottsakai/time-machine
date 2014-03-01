#ifndef FIFODISK_HH
#define FIFODISK_HH

#include <pcap.h>
#include <list>
#include <string>
#include <dirent.h>

#include "types.h"
#include "tm.h"
#include "Index.hh"

/* resolve circular header file dependency by forward declarations
 */
class QueryRequest;
class QueryResult;
class IntervalSet;

class FifoDiskFile;

class FifoDisk {
public:
	FifoDisk(const std::string& classname, uint64_t size,
			 uint64_t file_size, pcap_t*);
	~FifoDisk();
	//  void addPkt(const struct pcap_pkthdr *header, const unsigned char *packet);
	void addPkt(const pkt_ptr p);
	tm_time_t getStartTimestamp();
	tm_time_t getOldestTimestamp() const;
	tm_time_t getNewestTimestamp() const;
	uint64_t getHeldBytes() {
		return held_bytes;
	}
	uint64_t getHeldPkts() {
		return held_pkts;
	};
	std::list <FifoDiskFile*>::iterator filesBeginIt() {
		return files.begin();
	}
	std::list <FifoDiskFile*>::iterator filesEndIt() {
		return files.end();
	}
#ifdef QUERY_RACE_PROTECT
	void lockQueryInProgress() { 
		pthread_mutex_lock(&query_in_progress_mutex);
	}
	void unlockQueryInProgress() { 
		pthread_mutex_unlock(&query_in_progress_mutex);
	}
#else
	void lockQueryInProgress() {};
	void unlockQueryInProgress() {};
#endif

#ifdef QUERY_RACE_PROTECT
	void incQueryInProgress() {
		lockQueryInProgress();
		queries++;
		unlockQueryInProgress();
	}
	void decQueryInProgress() {
		lockQueryInProgress();
		queries++;
		unlockQueryInProgress();
	}
#else
	void incQueryInProgress() { };
	void decQueryInProgress() { };
#endif


protected:
	std::string classname;
	std::list <FifoDiskFile*> files;
	uint64_t size;
	uint64_t file_size;
	uint64_t tot_bytes;
	uint64_t tot_pkts;
	uint32_t file_number;
	pcap_t* pcap_handle;
	uint64_t held_bytes;
	uint64_t held_pkts;
	tm_time_t oldestTimestamp;
	tm_time_t newestTimestamp;
	pthread_mutex_t query_in_progress_mutex;
	int queries;
};


class FifoDiskFile {
public:
	FifoDiskFile(const std::string& filename, pcap_t*, int flags=FIFO_DISK_FILE_DEFAULT);
	~FifoDiskFile();
	void open();
	void close();
	void remove();
	void writePkt(const struct pcap_pkthdr *header, const unsigned char *packet);
	void addPkt(pkt_ptr p);
	int64_t getCurFileSize() {
		int64_t t;
		lockMetadata();
		t = cur_file_size;
		unlockMetadata();
		return t;
	}
	uint64_t getHeldBytes() {
		uint64_t t;
		lockMetadata();
		t = held_bytes;
		unlockMetadata();
		return t;
	}
	uint64_t getHeldPkts() {
		uint64_t t;
		lockMetadata();
		t = held_pkts;
		unlockMetadata();
		return t;
	}
	tm_time_t getOldestTimestamp() {
		return oldest_timestamp;
	}
	tm_time_t getNewestTimestamp() {
		return newest_timestamp;
	}
	std::string getFilename() {
		return filename;
	}
	bool flush() {
		return pcap_dump_flush(pcap_dumper_handle)==0;
	}

	bool valid() {
		return is_valid;
	}
	bool operator<(FifoDiskFile *rhs);

	/* iterator will be increased up to the first interval completeley
	   not in file */
	uint64_t query( QueryRequest*, QueryResult*, IntervalSet*);

	bool flushQueue();
protected:
	void loadStateFromSummary();
	void loadStateFromPcap();
	void loadState();
	void writeSummaryFile();

	void lockMetadata() {
		pthread_mutex_lock(&metadata_lock_mutex);
	};

	bool tryLockMetadata() {
		if (pthread_mutex_trylock(&metadata_lock_mutex) == 0) {
			return true;
		}
		return false;
	};

	void unlockMetadata() {
		pthread_mutex_unlock(&metadata_lock_mutex);
	};
		
	void lockQueue() {
		pthread_mutex_lock(&queue_lock_mutex);
	};

	bool tryLockQueue() {
		if (pthread_mutex_trylock(&queue_lock_mutex) == 0) {
			return true;
		}
		return false;
	};
	
	void unlockQueue() {
		pthread_mutex_unlock(&queue_lock_mutex);
	};


	std::string filename;
	bool is_open;
	bool is_valid;
	bool is_dirty;
	bool exit_writer;
	pcap_dumper_t *pcap_dumper_handle;
	int64_t cur_file_size;
	uint64_t held_bytes;
	uint64_t pkt_hdr_size;
	uint64_t held_pkts;
	pcap_t *pcap_handle;
	tm_time_t oldest_timestamp;
	tm_time_t newest_timestamp;
	pthread_mutex_t metadata_lock_mutex;
	pthread_mutex_t queue_lock_mutex;
	pthread_mutex_t write_cond_lock_mutex;
	pthread_cond_t  write_cond;
	pthread_t writer_thread;
	std::queue<pkt_ptr> writeQueue;
};



void* writerMain(void*);
bool FifoDiskFileCmp( FifoDiskFile *&lhs, FifoDiskFile *&rhs);
#endif /* FIFODISK_HH */
