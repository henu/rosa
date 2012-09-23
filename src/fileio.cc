#include "fileio.h"

#include "options.h"

#ifdef ENABLE_PROFILER
#include <hpp/profiler.h>
#endif
#include <hpp/serialize.h>
#include <hpp/cast.h>
#include <hpp/misc.h>
#include <hpp/aes256ofbcipher.h>
#include <hpp/random.h>
#include <cstring>
#include <iostream>

#ifdef ENABLE_FILEIO_CACHE
FileIO::FileIO(size_t readcache_max_size) :
#else
FileIO::FileIO(void) :
#endif
data_end(0),
#ifdef ENABLE_FILEIO_CACHE
readcache_max_size(readcache_max_size),
#else
readcache_max_size(0),
#endif
readcache_total_size(0),
journal_exists(false)
{
}

FileIO::~FileIO(void)
{
	if (!writecache.empty()) {
		std::cerr << "WARNING: There are unflushed writes!" << std::endl;
	}

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
	std::ios_base::openmode openmode = std::ios_base::binary | std::ios_base::in | std::ios_base::out;
	if (!path.exists()) {
		openmode |= std::ios_base::trunc;
	}

	file.open(path.toString().c_str(), openmode);
	if (!file.is_open()) {
		throw Hpp::Exception("Unable to open archive \"" + path.toString(true) + "\"!");
	}

}

void FileIO::enableCrypto(Hpp::ByteV const& crypto_key)
{
	this->crypto_key = crypto_key;
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

void FileIO::writeChunk(size_t offset, Hpp::ByteV const& chunk, bool encrypt)
{
	#ifdef ENABLE_PROFILER
	Hpp::Profiler prof("FileIO::writeChunk");
	#endif

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
		writecache.erase(writecache_find);
	}
	while ((writecache_find = writecache.lower_bound(offset)) != writecache.begin()) {
		-- writecache_find;
		if (writecache_find->first + writecache_find->second.data.size() <= offset) {
			break;
		}
		writecache.erase(writecache_find);
	}

	// Store new writechunk
	Writecachechunk new_chunk;
	new_chunk.encrypt = encrypt;
	new_chunk.data = chunk;
	writecache[offset] = new_chunk;
}

void FileIO::flushWrites(bool use_journal)
{
	#ifdef ENABLE_PROFILER
	Hpp::Profiler prof("FileIO::flushWrites");
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
			HppAssert(offset + data.size() <= data_end, "One of writes in cache overflows beyond data area!");
		}
		#endif

		// Write journal location to disk
		writeToDisk(getJournalInfoLocation(), Hpp::uInt64ToByteV(data_end));

		// Serialize journal to byte vector
		Hpp::ByteV journal_srz;
		for (Writecache::const_iterator writecache_it = writecache.begin();
		     writecache_it != writecache.end();
		     ++ writecache_it) {
			uint64_t offset = writecache_it->first;
			Writecachechunk const& chunk = writecache_it->second;
			journal_srz += Hpp::uInt64ToByteV(offset);
			if (chunk.encrypt) {
				journal_srz.push_back(Hpp::randomInt(0x80, 0xff));
			} else {
				journal_srz.push_back(Hpp::randomInt(0, 0x7f));
			}
			journal_srz += Hpp::uInt32ToByteV(chunk.data.size());
			journal_srz += chunk.data;
		}

		// Write journal to disk
		writeToDisk(data_end, Hpp::uInt64ToByteV(journal_srz.size()));
		writeToDisk(data_end + 8, journal_srz);
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
	}
	file.flush();

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
}

bool FileIO::finishPossibleInterruptedJournal(void)
{
	if (!getJournalFlag()) {
		return false;
	}

	// Read serialized journal
	uint64_t journal_loc = getJournalInfoLocation();
	uint64_t journal_srz_size = Hpp::cStrToUInt64(&readPart(journal_loc, 8)[0]);
	Hpp::ByteV journal_srz = readPart(journal_loc + 8, journal_srz_size);

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

void FileIO::clearJournalFlag(void)
{
	writeJournalflag(false);
	file.sync();
	journal_exists = false;
}

void FileIO::ensureArchiveSize(size_t size)
{
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
		flag_serialized.push_back(Hpp::randomInt(0x80, 0xff));
	} else {
		flag_serialized.push_back(Hpp::randomInt(0, 0x7f));
	}

	writeToDisk(getJournalFlagLocation(), flag_serialized);
}

void FileIO::writeToDisk(uint64_t offset, Hpp::ByteV const& data, bool encrypt)
{
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
