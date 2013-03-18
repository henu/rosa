#ifndef FILEIO_H
#define FILEIO_H

#include "useroptions.h"

#include <hpp/path.h>
#include <hpp/bytev.h>
#include <fstream>
#include <map>
#include <list>

// TODO: If archive is opened in read only mode, apply journal to read cache
class FileIO
{

public:

	FileIO(bool read_write_mode, Useroptions const& useroptions);
	~FileIO(void);

	// Opens file and closes old one if its open. Also resets everything.
	void closeAndOpenFile(Hpp::Path const& path);

	// Enables/disables crypto
	void enableCrypto(Hpp::ByteV const& crypto_key);

	// Updates end of all data (except journal)
	void setEndOfData(uint64_t data_end);

	// Writes journal flag to the first time and write it
	// false. This is called when archive is created.
	void initAndWriteJournalFlagToFalse(void);

	// Reads journal flag from disk. This is called when opening
	// file and after interrupted journal has been finished.
	void readJournalflagState(void);

	// Some getters
	inline bool getJournalFlag(void) const { return journal_exists; }

	// Reads one encryptable part from file. If encryption is
	// turned on, then the part will be decrypted automatically.
	Hpp::ByteV readPart(size_t offset, size_t size, bool do_not_decrypt = false);

	void initWrite(bool use_journal);

	// Adds encryptable chunk to the queue of writes. If encryption
	// is not wanted, then do_not_crypt must be enabled.
	void writeChunk(size_t offset, Hpp::ByteV const& chunk, bool encrypt = true);

	// Finish writes that are in queue either with journal or without it
	void deinitWrite(void);

	// Ensures everything is written to disk.
	void flush(void);

	// Reads and applies writes that are found from journal. If journal
	// does not exist, then this function does nothing. Returns true
	// whenever interrupted journal was found (and applied).
	bool finishPossibleInterruptedJournal(void);

	// Reduces file size to minimum possible.
	// Does nothing if journal exists.
	void shrinkFileToMinimumPossible(void);

private:

	struct Readcachechunk;
	typedef std::map< uint64_t, Readcachechunk* > Readcache;
	typedef std::list< Readcache::iterator > Readcachepriorities;
	struct Readcachechunk
	{
		Hpp::ByteV data;
		Readcachepriorities::iterator prior_it;
		bool prevent_releasing;
	};

	struct Writecachechunk
	{
		Hpp::ByteV data;
		bool encrypt;
	};
	typedef std::map< uint64_t, Writecachechunk > Writecache;
	enum WritecacheState { NOT_INITIALIZED, INITIALIZED_WITHOUT_JOURNAL, INITIALIZED_WITH_JOURNAL, WAITING_MORE_WITHOUT_JOURNAL, WAITING_MORE_WITH_JOURNAL };

	bool read_write_mode;
	Useroptions useroptions;

	std::fstream file;
	std::ios_base::openmode file_openmode;
	Hpp::Path file_path;

	// If "crypto_key" is empty, then it means encryption is not enabled.
	Hpp::ByteV crypto_key;

	// The position where all of data (except journal) ends.
	// This is used by journal to determine correct position
	// for it and it MUST be updated by the user!
	uint64_t data_end;

	Readcache readcache;
	Readcachepriorities readcache_priors;
	size_t readcache_total_size;

	Writecache writecache;
	WritecacheState writecache_state;
	size_t writecache_total_size;
	size_t writecache_data_end; // This tell what maximum data end has been

	// Is there journal or orphan nodes
	bool journal_exists;

	void clearJournalFlag(void);

	void ensureArchiveSize(size_t size);

	// Getters from some locations in archive
	uint64_t getJournalFlagLocation(void) const;
	uint64_t getJournalInfoLocation(void) const;

	// Writes for journal flag
	void writeJournalflag(bool journal_exists);

	// Actual writing function
	void writeToDisk(uint64_t offset, Hpp::ByteV const& data, bool encrypt = true);

	// Actual writecache writer
	void writeWritecacheToDisk(bool use_journal);

	// Generates initial vector for cipher, based on file offset
	static Hpp::ByteV generateCryptoIV(size_t offset);

	// Stores given chunk to cache. Also clears anything
	// that is even partly overlapping this new data.
	void storeToReadcache(uint64_t offset, Hpp::ByteV const& chunk,
	                      bool prevent_releasing_and_do_not_limit_storings);

	// Moves specific chunk to the front, so it will be the last
	// one that will be removed in case cache becomes full.
	void moveToFrontInReadcache(Readcache::iterator& readcache_find);

};

#endif
