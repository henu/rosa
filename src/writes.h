#ifndef WRITES_H
#define WRITES_H

#include <hpp/bytev.h>
#include <hpp/assert.h>
#include <map>

// Type for writes of bytes to different parts of file.
typedef std::map< uint64_t, Hpp::ByteV > Writes;

Writes writesJournalFlag(uint64_t journal_flag_loc, bool journal_exists);

// Use absolute position in bytes
Writes writesJournal(uint64_t journal_info_begin, uint64_t journal_begin, Writes const& journal);

inline Writes& operator+=(Writes& w1, Writes const& w2)
{
	for (Writes::const_iterator w2_it = w2.begin();
	     w2_it != w2.end();
	     ++ w2_it) {
		// Prepare
		uint64_t offset = w2_it->first;
		Hpp::ByteV const& data = w2_it->second;
		HppAssert(w1.find(offset) == w1.end(), "Trying to merge two Writes, but this will cause overlaps!");
		// Write
		w1[offset] = data;

	}
	return w1;
}

#endif
