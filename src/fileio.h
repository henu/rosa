#ifndef FILEIO_H
#define FILEIO_H

#include "writes.h"

#include <hpp/path.h>
#include <hpp/bytev.h>
#include <fstream>

class FileIO
{

public:

	FileIO(void);

	// Opens file and closes old one if its open. Also resets everything.
	void closeAndOpenFile(Hpp::Path const& path);

	// Enables/disables crypto
	void enableCrypto(Hpp::ByteV const& crypto_key);

	// Updates end of all data (except journal)
	inline void setEndOfData(uint64_t data_end) { this->data_end = data_end; }

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

	// Applies Writes to file
	void doWrites(Writes const& writes, bool do_not_crypt = false);

	// Applies first journal, then writes, and finally clear journal flag.
	void doJournalAndWrites(Writes const& writes);

	// Reads and applies writes that are found from journal. If journal
	// does not exist, then this function does nothing. Returns true
	// whenever interrupted journal was found (and applied).
	bool finishPossibleInterruptedJournal(void);

	// Flush buffered contents of files to the disk
	inline void flush(void) { file.flush(); }

private:

	#ifdef ENABLE_FILEIO_CACHE
	typedef std::map< uint64_t, Hpp::ByteV > Cache;
	#endif

	std::fstream file;

	Hpp::ByteV crypto_key;

	// The position where all of data (except journal) ends.
	// This is used by journal to determine correct position
	// for it and it MUST be updated by the user!
	uint64_t data_end;

	#ifdef ENABLE_FILEIO_CACHE
	Cache cache;
	#endif

	// Is there journal or orphan nodes
	bool journal_exists;

	void clearJournalFlag(void);

	void ensureArchiveSize(size_t size);

	// Getters from some locations in archive
	uint64_t getJournalFlagLocation(void) const;
	uint64_t getJournalInfoLocation(void) const;

	// Generates initial vector for cipher, based on file offset
	static Hpp::ByteV generateCryptoIV(size_t offset);

	// Stores given chunk to cache. Also clears anything
	// that is even partly overlapping this new data.
	#ifdef ENABLE_FILEIO_CACHE
	void storeToCache(uint64_t offset, Hpp::ByteV const& chunk);
	#endif

};

#endif
