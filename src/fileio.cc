#include "fileio.h"

#include "options.h"
#include "misc.h"

#ifdef ENABLE_PROFILER
#include <hpp/profiler.h>
#endif
#include <hpp/serialize.h>
#include <hpp/cast.h>
#include <hpp/misc.h>
#include <hpp/aes256ofbcipher.h>
#include <hpp/random.h>
#include <cstring>
#include <algorithm>

#ifdef ENABLE_FILEIO_CACHE
FileIO::FileIO(size_t writecache_max_size, size_t readcache_max_size) :
#else
FileIO::FileIO(size_t writecache_max_size) :
#endif
data_end(0),
#ifdef ENABLE_FILEIO_CACHE
readcache_max_size(readcache_max_size),
#else
readcache_max_size(0),
#endif
readcache_total_size(0),
writecache_state(NOT_INITIALIZED),
writecache_max_size(writecache_max_size),
writecache_total_size(0),
writecache_data_end(0),
journal_exists(false)
{
// TODO: If archive contains journal and is opened in read only method, then fix journal here and store it to memory!
// TODO: Also, make it so that FileIO is requested to open stuff either in read only mode, or read-write. And if journal needs to be fixed in read only mode, then it is somehow added to read cache with higher priority, so it wont get released ever.
}

FileIO::~FileIO(void)
{
	flush();
	HppAssert(writecache_state == NOT_INITIALIZED, "Invalid writecache state!");

	for (Readcache::iterator readcache_it = readcache.begin();
	     readcache_it != readcache.end();
	     ++ readcache_it) {
		delete readcache_it->second;
	}
}

void FileIO::closeAndOpenFile(Hpp::Path const& path)
{
	// Close possible old file
	if (file.is_open()) {
		file.close();
	}

	// If file already exists, then do not use trunc
	file_openmode = std::ios_base::binary | std::ios_base::in | std::ios_base::out;
	if (!path.exists()) {
		file_openmode |= std::ios_base::trunc;
	}

	file.open(path.toString().c_str(), file_openmode);
	if (!file.is_open()) {
		throw Hpp::Exception("Unable to open archive \"" + path.toString(true) + "\"!");
	}

	// In case of close/opens, remove trunc from flags
	file_openmode &= ~std::ios_base::trunc;

	file_path = path;
}

void FileIO::enableCrypto(Hpp::ByteV const& crypto_key)
{
	this->crypto_key = crypto_key;
}

void FileIO::setEndOfData(uint64_t data_end)
{
	this->data_end = data_end;
	writecache_data_end = std::max< size_t >(writecache_data_end, data_end);
}

void FileIO::initAndWriteJournalFlagToFalse(void)
{
	HppAssert(!journal_exists, "Journal must not exist now!");
	writeJournalflag(false);
}

void FileIO::readJournalflagState(void)
{
	journal_exists = (readPart(getJournalFlagLocation(), 1)[0] >= 128);
}

Hpp::ByteV FileIO::readPart(size_t offset, size_t size, bool do_not_decrypt)
{
	#ifdef ENABLE_PROFILER
	Hpp::Profiler prof("FileIO::readPart");
	#endif

	// Check if part exists in write cache
	Writecache::iterator writecache_find = writecache.find(offset);
// TODO: Would it be a good idea to always want data area that has same size?
	if (writecache_find != writecache.end() && writecache_find->second.data.size() == size) {
		return writecache_find->second.data;
	}

	// Check if part exists in read cache
	#ifdef ENABLE_FILEIO_CACHE
	Readcache::iterator readcache_find = readcache.find(offset);
	if (readcache_find != readcache.end() && readcache_find->second->data.size() == size) {
		moveToFrontInReadcache(readcache_find);
		return readcache_find->second->data;
	}
	#endif

	// Prepare
	Hpp::ByteV part;
	part.assign(size, 0);
	// Read bytes
	file.seekg(offset, std::ios_base::beg);
	file.read((char*)&part[0], size);
	// Check encryption
	if (do_not_decrypt || crypto_key.empty()) {
		#ifdef ENABLE_FILEIO_CACHE
		storeToReadcache(offset, part);
		#endif
		return part;
	} else {
		Hpp::ByteV part_decrypted;
		part_decrypted.reserve(size);
		Hpp::AES256OFBCipher cipher(crypto_key, generateCryptoIV(offset), false);
		cipher.decrypt(part);
		cipher.readDecrypted(part_decrypted, true);
		#ifdef ENABLE_FILEIO_CACHE
		storeToReadcache(offset, part_decrypted);
		#endif
		return part_decrypted;
	}
}

void FileIO::initWrite(bool use_journal)
{
	HppAssert(writecache_state != INITIALIZED_WITHOUT_JOURNAL && writecache_state != INITIALIZED_WITH_JOURNAL, "Writecache is already initialized!");

	// If we are not waiting for new writes, then just initialize normally
	if (writecache_state == NOT_INITIALIZED) {
		if (use_journal) {
			writecache_state = INITIALIZED_WITH_JOURNAL;
		} else {
			writecache_state = INITIALIZED_WITHOUT_JOURNAL;
		}
		writecache_data_end = data_end;
	}
	// If we are waiting for more writes, but without journal, and next
	// writes use journal, then write pending stuff to disk first.
	else if (writecache_state == WAITING_MORE_WITHOUT_JOURNAL && use_journal) {
		writeWritecacheToDisk(false);
		writecache_state = INITIALIZED_WITH_JOURNAL;
		writecache_data_end = data_end;
	}
	// If we are already waiting with journal,
	// then keep using it with these writes too.
	else if (writecache_state == WAITING_MORE_WITH_JOURNAL) {
		writecache_state = INITIALIZED_WITH_JOURNAL;
		HppAssert(writecache_data_end >= data_end, "writecache_data_end is too small!");
	}
	// Otherwise we are not waiting with journal and
	// do not want to use it with these writes either.
	else {
		HppAssert(writecache_state == WAITING_MORE_WITHOUT_JOURNAL, "Wrong state!");
		HppAssert(!use_journal, "Wrong flag!");
		writecache_state = INITIALIZED_WITHOUT_JOURNAL;
		HppAssert(writecache_data_end >= data_end, "writecache_data_end is too small!");
	}
}

void FileIO::writeChunk(size_t offset, Hpp::ByteV const& chunk, bool encrypt)
{
	#ifdef ENABLE_PROFILER
	Hpp::Profiler prof("FileIO::writeChunk");
	#endif

	HppAssert(writecache_state == INITIALIZED_WITHOUT_JOURNAL || writecache_state == INITIALIZED_WITH_JOURNAL, "Writecache is not initialized!");

	uint64_t end = offset + chunk.size();

	// Remove possible overlapping chunks from readcache and from
	// writecache. Start from those that begin after this one
	Readcache::iterator readcache_find;
	while ((readcache_find = readcache.lower_bound(offset)) != readcache.end()) {
		if (readcache_find->first >= end) {
			break;
		}
		readcache_total_size -= readcache_find->second->data.size();
		readcache_priors.erase(readcache_find->second->prior_it);
		delete readcache_find->second;
		readcache.erase(readcache_find);
	}
	// Then clear those that begin before this new one
	while ((readcache_find = readcache.lower_bound(offset)) != readcache.begin()) {
		-- readcache_find;
		if (readcache_find->first + readcache_find->second->data.size() <= offset) {
			break;
		}
		readcache_total_size -= readcache_find->second->data.size();
		readcache_priors.erase(readcache_find->second->prior_it);
		delete readcache_find->second;
		readcache.erase(readcache_find);
	}
	// Then do same for writecache
	Writecache::iterator writecache_find;
	while ((writecache_find = writecache.lower_bound(offset)) != writecache.end()) {
		if (writecache_find->first >= end) {
			break;
		}
		writecache_total_size -= writecache_find->second.data.size();
		writecache.erase(writecache_find);
	}
	while ((writecache_find = writecache.lower_bound(offset)) != writecache.begin()) {
		-- writecache_find;
		if (writecache_find->first + writecache_find->second.data.size() <= offset) {
			break;
		}
		writecache_total_size -= writecache_find->second.data.size();
		writecache.erase(writecache_find);
	}

	// Store new writechunk
	Writecachechunk new_chunk;
	new_chunk.encrypt = encrypt;
	new_chunk.data = chunk;
	writecache[offset] = new_chunk;
	writecache_total_size += chunk.size();
}

void FileIO::deinitWrite(void)
{
	HppAssert(writecache_state == INITIALIZED_WITHOUT_JOURNAL || writecache_state == INITIALIZED_WITH_JOURNAL, "Writecache is not initialized!");

	// If size of writecache has exceeded its
	// maximum limit, then write it immediately.
	if (writecache_total_size > writecache_max_size) {
		writeWritecacheToDisk(writecache_state == INITIALIZED_WITH_JOURNAL);
		writecache_state = NOT_INITIALIZED;
	}
	// If limit is not exceeded, then it is good idea to wait
	// for more writes, and then write all of them at once.
	else if (writecache_state == INITIALIZED_WITHOUT_JOURNAL) {
		writecache_state = WAITING_MORE_WITHOUT_JOURNAL;
	} else {
		HppAssert(writecache_state == INITIALIZED_WITH_JOURNAL, "Wrong state!");
		writecache_state = WAITING_MORE_WITH_JOURNAL;
	}
}

void FileIO::flush(void)
{
	if (writecache_state == WAITING_MORE_WITHOUT_JOURNAL) {
		writeWritecacheToDisk(false);
	} else if (writecache_state == WAITING_MORE_WITH_JOURNAL) {
		writeWritecacheToDisk(true);
	}
	writecache_state = NOT_INITIALIZED;
}

bool FileIO::finishPossibleInterruptedJournal(void)
{
	if (!getJournalFlag()) {
		return false;
	}

	// Read serialized journal
	uint64_t journal_info_loc = getJournalInfoLocation();
	uint64_t journal_loc = Hpp::cStrToUInt64(&readPart(journal_info_loc, 8)[0]);
	uint64_t journal_srz_size = Hpp::cStrToUInt32(&readPart(journal_loc, 4)[0]);
	Hpp::ByteV journal_srz = readPart(journal_loc + 4, journal_srz_size);

	// Deserialize journal
	Hpp::ByteV::const_iterator journal_srz_it = journal_srz.begin();
	while (journal_srz_it != journal_srz.end()) {
		uint64_t begin = Hpp::deserializeUInt64(journal_srz_it, journal_srz.end());
		bool encrypt = Hpp::deserializeUInt8(journal_srz_it, journal_srz.end()) >= 0x80;
		uint32_t size = Hpp::deserializeUInt32(journal_srz_it, journal_srz.end());
		Hpp::ByteV data = Hpp::deserializeByteV(journal_srz_it, journal_srz.end(), size);
		writeToDisk(begin, data, encrypt);
	}

	// Finally clear journal flag
	clearJournalFlag();

	return true;

}

void FileIO::shrinkFileToMinimumPossible(void)
{
	if (journal_exists) {
		return;
	}

	// First write everything to disk
	flush();
	HppAssert(writecache_state == NOT_INITIALIZED, "Invalid writecache state!");

	// Close file, so it can be safely truncated
	file.close();

	// Truncate
	file_path.resizeFile(data_end);

	// Open file again
	file.open(file_path.toString().c_str(), file_openmode);
	if (!file.is_open()) {
		throw Hpp::Exception("Unable to open archive \"" + file_path.toString(true) + "\" after it was resized!");
	}

	// Remove everything from read cache that is at removed area
	#ifdef ENABLE_FILEIO_CACHE
	Readcache::iterator readcache_it = readcache.begin();
	while (readcache_it != readcache.end()) {
		uint64_t chunk_begin = readcache_it->first;
		Readcachechunk* chunk = readcache_it->second;
		if (chunk_begin + chunk->data.size() > data_end) {
			// Reduce total size and delete actual chunk
			readcache_total_size -= chunk->data.size();
			delete chunk;
			// Remove iterator from priorities
			Readcachepriorities::iterator readcache_priors_find = std::find(readcache_priors.begin(), readcache_priors.end(), readcache_it);
			HppAssert(readcache_priors_find != readcache_priors.end(), "Chunk iterator not found from priorities!");
			readcache_priors.erase(readcache_priors_find);
			// Remove from cache
			readcache.erase(readcache_it ++);
		} else {
			++ readcache_it;
		}
	}
	#endif
}

void FileIO::clearJournalFlag(void)
{
	writeJournalflag(false);
	file.flush();
	journal_exists = false;
}

void FileIO::ensureArchiveSize(size_t size)
{
	#ifdef ENABLE_PROFILER
	Hpp::Profiler prof("FileIO::ensureArchiveSize");
	#endif
	size_t const WRITE_BUF_SIZE = 128;
	char write_buf[WRITE_BUF_SIZE];
	#ifndef NDEBUG
	Hpp::toZero(write_buf, WRITE_BUF_SIZE);
	#endif

	file.seekp(0, std::ios_base::end);
	size_t size_now = file.tellp();
	while (size_now < size) {
		size_t write_amount = std::min(size_now - size, WRITE_BUF_SIZE);
		file.write(write_buf, write_amount);
		size_now += write_amount;
	}
}

uint64_t FileIO::getJournalFlagLocation(void) const
{
	// Archive identifier, version and crypto flag
	size_t result = strlen(ARCHIVE_IDENTIFIER) + 2;
	// Possible salt and password verifier
	if (!crypto_key.empty()) {
		result += SALT_SIZE + PASSWORD_VERIFIER_SIZE;
	}
	// Journal flag
	return result;
}

uint64_t FileIO::getJournalInfoLocation(void) const
{
	return getJournalFlagLocation() + 1;
}

void FileIO::writeJournalflag(bool journal_exists)
{
	Hpp::ByteV flag_serialized;
	if (journal_exists) {
		flag_serialized.push_back(secureRandomInt(0x80, 0xff, !crypto_key.empty()));
	} else {
		flag_serialized.push_back(secureRandomInt(0, 0x7f, !crypto_key.empty()));
	}

	writeToDisk(getJournalFlagLocation(), flag_serialized);
}

void FileIO::writeToDisk(uint64_t offset, Hpp::ByteV const& data, bool encrypt)
{
	#ifdef ENABLE_PROFILER
	Hpp::Profiler prof("FileIO::writeToDisk");
	#endif

	file.seekp(offset, std::ios_base::beg);
	if (crypto_key.empty() || !encrypt) {
		file.write((char const*)&data[0], data.size());
	} else {
		Hpp::ByteV data_crypted;
		Hpp::AES256OFBCipher cipher(crypto_key, generateCryptoIV(offset), false);
		cipher.encrypt(data);
		cipher.readEncrypted(data_crypted, true);
		file.write((char const*)&data_crypted[0], data_crypted.size());
	}
}

void FileIO::writeWritecacheToDisk(bool use_journal)
{
	#ifdef ENABLE_PROFILER
	Hpp::Profiler prof("FileIO::writeWritecacheToDisk");
	#endif

	// Write journal, if its wanted
	if (use_journal) {
		// First ensure there is no journal already
		if (journal_exists) {
			throw Hpp::Exception("There is already journal!");
		}

		// Ensure none of writes go over the end of data
		#ifndef NDEBUG
		for (Writecache::const_iterator writecache_it = writecache.begin();
		     writecache_it != writecache.end();
		     ++ writecache_it) {
			uint64_t offset = writecache_it->first;
			Hpp::ByteV const& data = writecache_it->second.data;
			HppAssert(offset + data.size() <= writecache_data_end, "One of writes in cache overflows beyond data area!");
		}
		#endif

		// Write journal location to disk
		writeToDisk(getJournalInfoLocation(), Hpp::uInt64ToByteV(writecache_data_end));

		// Serialize journal to byte vector
		Hpp::ByteV journal_srz;
		for (Writecache::const_iterator writecache_it = writecache.begin();
		     writecache_it != writecache.end();
		     ++ writecache_it) {
			uint64_t offset = writecache_it->first;
			Writecachechunk const& chunk = writecache_it->second;
			journal_srz += Hpp::uInt64ToByteV(offset);
			if (chunk.encrypt) {
				journal_srz.push_back(secureRandomInt(0x80, 0xff, !crypto_key.empty()));
			} else {
				journal_srz.push_back(secureRandomInt(0, 0x7f, !crypto_key.empty()));
			}
			journal_srz += Hpp::uInt32ToByteV(chunk.data.size());
			journal_srz += chunk.data;
		}

		// Write journal to disk
		writeToDisk(writecache_data_end, Hpp::uInt32ToByteV(journal_srz.size()));
		writeToDisk(writecache_data_end + 4, journal_srz);
		file.flush();

		// Write journal flag to disk
		writeJournalflag(true);
		journal_exists = true;
		file.flush();

	}

	// Now do actual writes
	for (Writecache::const_iterator writecache_it = writecache.begin();
	     writecache_it != writecache.end();
	     ++ writecache_it) {
		uint64_t offset = writecache_it->first;
		Writecachechunk const& chunk = writecache_it->second;
		writeToDisk(offset, chunk.data, chunk.encrypt);
		#ifndef NDEBUG
		writecache_total_size -= chunk.data.size();
		#endif
	}
	file.flush();
	#ifndef NDEBUG
	HppAssert(writecache_total_size == 0, "Writecache total size calculator has failed!");
	#endif

	// Finally clear journal flag
	clearJournalFlag();

	// Clear writecache, but first move chunks to readcache
	#ifdef ENABLE_FILEIO_CACHE
	for (Writecache::const_iterator writecache_it = writecache.begin();
	     writecache_it != writecache.end();
	     ++ writecache_it) {
		uint64_t offset = writecache_it->first;
		Writecachechunk const& chunk = writecache_it->second;

		storeToReadcache(offset, chunk.data);
	}
	#endif
	writecache.clear();
	writecache_total_size = 0;
}

Hpp::ByteV FileIO::generateCryptoIV(size_t offset)
{
	Hpp::ByteV result(8, 0);
	result.reserve(16);
	result += Hpp::uInt64ToByteV(offset);
	return result;
}

#ifdef ENABLE_FILEIO_CACHE
void FileIO::storeToReadcache(uint64_t offset, Hpp::ByteV const& chunk)
{
	if (chunk.size() >= readcache_max_size / 2) {
		return;
	}

	uint64_t end = offset + chunk.size();
	Readcache::iterator readcache_find;
	// Clear overlapping chunks. Start from
	// those that begin after this new one
	while ((readcache_find = readcache.lower_bound(offset)) != readcache.end()) {
		if (readcache_find->first >= end) {
			break;
		}
		readcache_total_size -= readcache_find->second->data.size();
		readcache_priors.erase(readcache_find->second->prior_it);
		delete readcache_find->second;
		readcache.erase(readcache_find);
	}
	// Then clear those that begin before this new one
	while ((readcache_find = readcache.lower_bound(offset)) != readcache.begin()) {
		-- readcache_find;
		if (readcache_find->first + readcache_find->second->data.size() <= offset) {
			break;
		}
		readcache_total_size -= readcache_find->second->data.size();
		readcache_priors.erase(readcache_find->second->prior_it);
		delete readcache_find->second;
		readcache.erase(readcache_find);
	}

	// Store
	Readcachechunk* new_chunk = new Readcachechunk;
	try {
		new_chunk->data = chunk;
		std::pair< Readcache::iterator, bool > insert_result = readcache.insert(Readcache::value_type(offset, new_chunk));
		HppAssert(insert_result.second, "There was already a value there!");
		readcache_priors.push_front(insert_result.first);
		new_chunk->prior_it = readcache_priors.begin();
	}
	catch ( ... ) {
		delete new_chunk;
		throw;
	}

	readcache_total_size += chunk.size();

	// If cache has grown too big, then remove oldest elements from it
	while (readcache_total_size > readcache_max_size) {
		Readcache::iterator oldest = readcache_priors.back();
		readcache_total_size -= oldest->second->data.size();
		delete oldest->second;
		readcache.erase(oldest);
		readcache_priors.pop_back();
	}
}

void FileIO::moveToFrontInReadcache(Readcache::iterator& readcache_find)
{
	readcache_priors.erase(readcache_find->second->prior_it);
	readcache_priors.push_front(readcache_find);
	readcache_find->second->prior_it = readcache_priors.begin();
}

#endif
