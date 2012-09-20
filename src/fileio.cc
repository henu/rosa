#include "fileio.h"

#include "options.h"

#ifdef ENABLE_PROFILER
#include <hpp/profiler.h>
#endif
#include <hpp/serialize.h>
#include <hpp/cast.h>
#include <hpp/misc.h>
#include <hpp/aes256ofbcipher.h>
#include <cstring>

#ifdef ENABLE_FILEIO_CACHE
FileIO::FileIO(size_t cache_max_size) :
#else
FileIO::FileIO(void) :
#endif
data_end(0),
#ifdef ENABLE_FILEIO_CACHE
cache_max_size(cache_max_size),
#endif
cache_total_size(0),
journal_exists(false)
{
}

FileIO::~FileIO(void)
{
	for (Cache::iterator cache_it = cache.begin();
	     cache_it != cache.end();
	     ++ cache_it) {
		delete cache_it->second;
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
	writesJournalFlag(getJournalFlagLocation(), false);
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

	// Check if part exists in cache
	#ifdef ENABLE_FILEIO_CACHE
	Cache::iterator cache_find = cache.find(offset);
	if (cache_find != cache.end() && cache_find->second->data.size() == size) {
		moveToFrontInCache(cache_find);
		return cache_find->second->data;
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
		storeToCache(offset, part);
		#endif
		return part;
	} else {
		Hpp::ByteV part_decrypted;
		part_decrypted.reserve(size);
		Hpp::AES256OFBCipher cipher(crypto_key, generateCryptoIV(offset), false);
		cipher.decrypt(part);
		cipher.readDecrypted(part_decrypted, true);
		#ifdef ENABLE_FILEIO_CACHE
		storeToCache(offset, part_decrypted);
		#endif
		return part_decrypted;
	}
}

void FileIO::doWrites(Writes const& writes, bool do_not_crypt)
{
	#ifdef ENABLE_PROFILER
	Hpp::Profiler prof("FileIO::doWrites");
	#endif

	// Ensure writes do not overlap
	#ifndef NDEBUG
	size_t last_end = 0;
	for (Writes::const_iterator writes_it = writes.begin();
	     writes_it != writes.end();
	     ++ writes_it) {
		// Get specs
		uint64_t begin = writes_it->first;
		uint64_t end = begin + writes_it->second.size();
		HppAssert(begin >= last_end, "Unable to do writes, because there are some that overlap!");
		last_end = end;
	}
	#endif
	// Do writes
	for (Writes::const_iterator writes_it = writes.begin();
	     writes_it != writes.end();
	     ++ writes_it) {
		// Get specs
		uint64_t offset = writes_it->first;
		Hpp::ByteV const& data = writes_it->second;

		ensureArchiveSize(offset);

		// Write
		file.seekp(offset, std::ios_base::beg);
		if (crypto_key.empty() || do_not_crypt) {
			file.write((char const*)&data[0], data.size());
		} else {
			Hpp::ByteV data_crypted;
			Hpp::AES256OFBCipher cipher(crypto_key, generateCryptoIV(offset), false);
			cipher.encrypt(data);
			cipher.readEncrypted(data_crypted, true);
			file.write((char const*)&data_crypted[0], data_crypted.size());
		}

		#ifdef ENABLE_FILEIO_CACHE
		storeToCache(offset, data);
		#endif
	}
}

void FileIO::doJournalAndWrites(Writes const& writes)
{

	// First ensure there is no journal already
	if (journal_exists) {
		throw Hpp::Exception("There is already journal!");
	}

	// Ensure none of writes go over end of data
	#ifndef NDEBUG
	for (Writes::const_iterator writes_it = writes.begin();
	     writes_it != writes.end();
	     ++ writes_it) {
		uint64_t offset = writes_it->first;
		Hpp::ByteV const& data = writes_it->second;
		HppAssert(offset + data.size() <= data_end, "One of writes overflow beyond data area!");
	}
	#endif

	// Write journal to disk
	doWrites(writesJournal(getJournalInfoLocation(), data_end, writes));
	file.flush();

	// Write journal flag to disk
	doWrites(writesJournalFlag(getJournalFlagLocation(), true));
	file.flush();

	// Now do writes
	doWrites(writes);

	// Finally clear journal flag
	clearJournalFlag();
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
	Writes journal;
	while (journal_srz_it != journal_srz.end()) {
		uint64_t begin = Hpp::deserializeUInt64(journal_srz_it, journal_srz.end());
		uint32_t size = Hpp::deserializeUInt32(journal_srz_it, journal_srz.end());
		if (journal.find(begin) != journal.end()) {
			throw Hpp::Exception("Invalid journal! Multiple writes begin from same location!");
		}
		journal[begin] = Hpp::deserializeByteV(journal_srz_it, journal_srz.end(), size);
	}

	// Do writes
	doWrites(journal);

	// Finally clear journal flag
	clearJournalFlag();

	return true;

}

void FileIO::clearJournalFlag(void)
{
	Writes writes = writesJournalFlag(getJournalFlagLocation(), false);
	doWrites(writes);
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

Hpp::ByteV FileIO::generateCryptoIV(size_t offset)
{
	Hpp::ByteV result(8, 0);
	result.reserve(16);
	result += Hpp::uInt64ToByteV(offset);
	return result;
}

#ifdef ENABLE_FILEIO_CACHE
void FileIO::storeToCache(uint64_t offset, Hpp::ByteV const& chunk)
{
	if (chunk.size() >= cache_max_size / 2) {
		return;
	}

	uint64_t end = offset + chunk.size();
	Cache::iterator cache_find;
	// Clear overlapping chunks. Start from
	// those that begin after this new one
	while ((cache_find = cache.lower_bound(offset)) != cache.end()) {
		if (cache_find->first >= end) {
			break;
		}
		cache_total_size -= cache_find->second->data.size();
		cache_priors.erase(cache_find->second->prior_it);
		delete cache_find->second;
		cache.erase(cache_find);
	}
	// Then clear those that begin before this new one
	while ((cache_find = cache.lower_bound(offset)) != cache.begin()) {
		-- cache_find;
		if (cache_find->first + cache_find->second->data.size() <= offset) {
			break;
		}
		cache_total_size -= cache_find->second->data.size();
		cache_priors.erase(cache_find->second->prior_it);
		delete cache_find->second;
		cache.erase(cache_find);
	}

	// Store
	Cacheitem* new_citem = new Cacheitem;
	try {
		new_citem->data = chunk;
		std::pair< Cache::iterator, bool > insert_result = cache.insert(Cache::value_type(offset, new_citem));
		HppAssert(insert_result.second, "There was already a value there!");
		cache_priors.push_front(insert_result.first);
		new_citem->prior_it = cache_priors.begin();
	}
	catch ( ... ) {
		delete new_citem;
		throw;
	}

	cache_total_size += chunk.size();

	// If cache has grown too big, then remove oldest elements from it
	while (cache_total_size > cache_max_size) {
		Cache::iterator oldest = cache_priors.back();
		cache_total_size -= oldest->second->data.size();
		delete oldest->second;
		cache.erase(oldest);
		cache_priors.pop_back();
	}
}

void FileIO::moveToFrontInCache(Cache::iterator& cache_find)
{
	cache_priors.erase(cache_find->second->prior_it);
	cache_priors.push_front(cache_find);
	cache_find->second->prior_it = cache_priors.begin();
}

#endif
