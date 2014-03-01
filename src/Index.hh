#ifndef INDEX_HH
#define INDEX_HH

#include <iostream>
#include <fstream>
#include <list>
#include <set>
#include <deque>
#include <queue>
#include <pcap.h>
#include <sstream>
#include <pthread.h>
#include <time.h>

#include "types.h"
#include "tm.h"
#include "IndexEntry.hh"
#include "IndexField.hh"
#include "DiskIndex.hh"
#include "IndexHash.hh"

/* forward declaration */
class Storage;

extern "C" { void *start_index_thread(void *instance); }
/**
 * Threading issues:
 * 
 * The CaptureThread will call the addPkt() method. The addPkt() method
 * will convert the pcap-header and packet data into an IndexField class,
 * enqueue this IndexField instance for further processing and signal the
 * thread maintaining this index, that new data has arrived. The work of 
 * the CaptureThread is then finished. 
 *
 * For each Index an IndexThread is reponsible for maintaining the index.
 * The implementation of this thread is the run() method. 
 * The IndexThread sleeps until it gets signaled that IndexField(s) have been
 * queued by the CaptureThread. It will then remove the IndexField from
 * the queue, store it in the internal hash and it will also do hash 
 * maintance (roatating hashes, writing entries to  to disk). 
 *
 * The indexAggregationThread is a global thread, that is woken
 * up every couple of seconds. This thread will call the aggregate()
 * methods of all threads. See DiskIndex.hh for a descpriton of the thread
 * handling there. 
 *
 * Various QueryThreads may be running. These may call lookupMem() and 
 * lookupDisk(). LookupDisk() is handled by DiskIndex. Have a look at
 * DiskIndex.hh for information on threads for the disk index.
 *
 * Locks, condtion vars and shared members: 
 *    
 *    + input_q, oldestTimestampMem and oldestTimestampDisk are protected
 *    by the lock_queue(), unlock_queue(). 
 *    + cond_broadcast_queue() is uses to indicated that new data has been 
 *    queued in input_q
 *    + the cur and old hashes are protected by lock_hash(), unlock_hash()
 *
 */

/* This queue is filled by the capture thread with IndexField *s
 * the index threads then read from the queue and update their 
 * hash tables
 * We used a std::queue before, but using an array as a Fifo as we 
 * do now gives much better performance. 
 * XXX: Find a good estimate for maximun queue size. We can just make
 * the queue rather large, a handfull ov KB or MB of "wasted" memory
 * in the queue shouldn't matter too much
 */
class MyQueue {
	public:
		MyQueue(unsigned maxsize) : maxsize(maxsize), entries(0), wp(0), rp(0) {
			q = new IndexField*[maxsize];
			drops=0;
			//fprintf(stderr, "MyQueue: maxsize=%u\n", maxsize);
		}
		~MyQueue() {
			while(!empty()) {
				delete back();
				pop_back();
			}
			delete []q;
		}
		IndexField * back() {
			if (entries>0)
				return q[rp];
			else
				return NULL;
		}
		void pop_back() {
			if (entries>0) {
				rp++;
				entries--;
				if (rp>=maxsize)
					rp = 0;
			}
		}
		void push_front (IndexField *elem) {
			if (drops%10000==1) {
				tmlog(TM_LOG_ERROR, "idx_queue", "Queue is full. IndexEntries were dropped (%d)", drops);
			}
			if (entries>=maxsize) {
				drops++;
				delete elem;
				return;
			}

#ifdef TM_HEAVY_DEBUG
			assert(rp!=wp || entries==0);
#endif
			drops = 0;
			q[wp] = elem;
			wp++;
			entries++;
			if (wp>=maxsize) 
				wp = 0;
		}

		unsigned size() const {
			return entries;
		}
		bool empty() const {
			return (entries==0);
		}
			

	protected: 
		IndexField **q;
		unsigned drops;
		unsigned maxsize;
		unsigned entries;
		unsigned wp, rp;
};

/*** 
 * IndexType is the base class of the Index<T> classes. It's
 * sole purpose is to present a common interface for all
 * Indexes.
 */
class IndexType {
public:
	virtual ~IndexType() {};

	virtual void cancelThread() = 0;
	/** Main method of index maintainer thread */
	virtual void run() = 0;
	/** The caputre thread calls addPkt. addPkt extracts the appropriate 
	 * index entries from the packet and enqueues the keys as IndexQueueEntry
	 * objects */
	virtual void addPkt(const pcap_pkthdr* header, const u_char* packet)=0;
	/** Set the storage class for this IndexType. 
	 *  TODO: we might want to make storage a global singleton ... 
	 */
	virtual void setStorage(Storage *arg_storage)=0;
	virtual const std::string getIndexName()=0;
	virtual uint64_t getNumEntriesRAM()=0;
	virtual uint64_t getNumEntriesDisk()=0;
	/** Look for a specfic entry in the index. Only look in the hashes in 
	 * mein memory */
	virtual void lookupMem(IntervalSet*,  IndexField*) = 0;
	/** Look for a specfic entry in the index. Only look in the index entries on 
	 * disk */
	virtual void lookupDisk(IntervalSet*,
							IndexField*, tm_time_t, tm_time_t) = 0;
	virtual IndexField* parseQuery(const char* query) = 0;
	virtual unsigned getQlen() const = 0;
	virtual void debugPrint() const = 0;
	virtual void debugPrint(FILE *fp) const = 0;
	pthread_t maintainer_thread;
protected:
	pthread_mutex_t hash_lock_mutex;
	pthread_mutex_t queue_lock_mutex;
	pthread_cond_t queue_cond;
	void lock_hash() {
		pthread_mutex_lock(&hash_lock_mutex);
	}
	void unlock_hash() {
		pthread_mutex_unlock(&hash_lock_mutex);
	}
	void lock_queue() {
		pthread_mutex_lock(&queue_lock_mutex);
	}
	void unlock_queue() {
		pthread_mutex_unlock(&queue_lock_mutex);
	}
	/** 
	 * Signal the MaintainerThread, that we added something to the queue.
	 * YOU MUST HOLD THE queue_lock WHEN CALLING THIS */
	void cond_broadcast_queue() {
		pthread_cond_broadcast(&queue_cond);
	}
	/** 
	 * Wait for signal, that data is availabe in the queue 
	 * YOU MUST HOLD THE queue_lock WHEN CALLING THIS */
	void cond_wait_queue() { 
		pthread_cond_wait(&queue_cond, &queue_lock_mutex);
	}
};


/***************************************************************************
 * class Index<T>
 *
 * This class handles one index. Indexes are supposed to be multithreaded.
 *
 * Internal Organization:
 * TODO
 *    
 *
 *
 */

template <class T> class Index: public IndexType {
public:
	// rot_offset is a (small) offset to delay the rotation and thus the writing of
	// the index to disk. This should be used 
	Index(tm_time_t d_t, uint32_t hash_size, bool do_disk_index, Storage * storage);
	~Index();
	void cancelThread();
	void lookupMem(IntervalSet* set, IndexField* key);
	void lookupDisk(IntervalSet* set, IndexField* key, tm_time_t t0, tm_time_t t1);
	void addPkt(const pcap_pkthdr* header, const u_char* packet);
	void setStorage(Storage *arg_storage) {
		storage = arg_storage;
	}
	void run();
	virtual const std::string getIndexName() {
		return T::getIndexNameStatic();
	}
	virtual IndexField* parseQuery(const char* query) {
		return T::parseQuery(query);
	}
	virtual uint64_t getNumEntriesRAM() {
		uint64_t n;
		lock_hash();
		n = old->getNumEntries() + cur->getNumEntries();
		unlock_hash();
		return n;
	}
	virtual uint64_t getNumEntriesDisk() {
		return num_entries_disk;
	}
	unsigned getQlen() const {
		return input_q.size();
	}
	void debugPrint() const;
	void debugPrint(FILE *fp) const;
protected:
	MyQueue input_q;
	//std::deque<IndexField *> input_q;
	/* cap_thread_oldestTimestamp{Mem|Disk} are updated by addPkt and 
	 * are protected by lock_queue() and unlock_queue(). I.e. they are
	 * set from the capture thread. 
	 *
	 * idx_thread_* are read by functions running with index thread 
	 * context. run() will copy the cap_* variables to idx_* variables
	 * while holding the queue lock.
	 */
	tm_time_t cap_thread_oldestTimestampDisk;
	tm_time_t cap_thread_oldestTimestampMem;
	tm_time_t cap_thread_iat; // InterArrivalTime 
	tm_time_t idx_thread_oldestTimestampDisk;
	tm_time_t idx_thread_oldestTimestampMem;
	tm_time_t idx_thread_iat; // InterArrivalTime 

	IndexFiles<T> *disk_index;
	tm_time_t d_t;
	tm_time_t last_rotated;
	tm_time_t last_updated;  // last packet ts to be added to hash
	IndexHash *cur, *old;
	uint64_t num_entries_ram, num_entries_disk;
	Storage *storage;
	int rotate_count;

	// You must hold the hash lock (lock_hash(), unlock_hash()) before calling addEntry() 
	void addEntry(IndexField *iqe);

	int qlen;

};


/***************************************************************************
 * class Indexes
 *
 * An Index Object that is added to Indexes is owned by Indexes 
 * I.e. Indexes will take care of deallocation the storage for
 * Index.
 */
extern unsigned had_to_wait;
class Indexes {
public:
	Indexes() {
		last_write_ts = 0;
		pthread_mutex_init(&disk_write_mutex, NULL);
	}
	~Indexes() {
		pthread_mutex_destroy(&disk_write_mutex);
		for (std::list<IndexType*>::iterator i=begin(); i!=end(); i++)
			delete (*i);
	}
	void setStorage(Storage *s) {
		for (std::list<IndexType*>::iterator i=begin(); i!=end(); i++)
			( *i)->setStorage(s);
	}
	void startThread() {
		for (std::list<IndexType*>::iterator i=begin(); i!=end(); i++)
			pthread_create(&((*i)->maintainer_thread), NULL, start_index_thread, (*i));
	}
	void cancelThread() {
		for (std::list<IndexType*>::iterator i=begin(); i!=end(); i++)
			( *i)->cancelThread();
	}
	bool addIndex(IndexType* i) {
		if (getIndexByName(i->getIndexName())) return false;
		indexes.push_back(i);
		return true;
	};
	IndexType* getIndexByName(std::string name) {
		for (std::list<IndexType*>::iterator i=indexes.begin();
				i!=indexes.end();
				i++)
			if ((*i)->getIndexName()==name) return (*i);
		return NULL;
	};
	int trylockDiskWrite() {
		struct timeval tmptv;
		gettimeofday(&tmptv, NULL);
		if (to_tm_time(&tmptv) - last_write_ts < IDX_MIN_TIME_BETWEEN_WRITES) {
			had_to_wait++;
			return EBUSY;
		}
		return pthread_mutex_trylock(&disk_write_mutex);
	}
	void unlockDiskWrite() {
		struct timeval tmptv;
		gettimeofday(&tmptv, NULL);
		last_write_ts = to_tm_time(&tmptv);
		pthread_mutex_unlock(&disk_write_mutex);
	}
	std::list<IndexType*>::iterator begin() {
		return indexes.begin();
	}
	std::list<IndexType*>::iterator end() {
		return indexes.end();
	}
protected:
	std::list<IndexType*> indexes;
	pthread_mutex_t disk_write_mutex;
	tm_time_t last_write_ts;
};


#include "Index.cc"



#endif
