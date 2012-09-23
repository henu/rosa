#include "writes.h"

#include <hpp/random.h>
#include <hpp/cast.h>

Writes writesJournalFlag(uint64_t journal_flag_loc, bool journal_exists)
{
	Hpp::ByteV flag_serialized;
	if (journal_exists) {
		flag_serialized.push_back(Hpp::randomInt(128, 255));
	} else {
		flag_serialized.push_back(Hpp::randomInt(0, 127));
	}

	Writes result;
	result[journal_flag_loc] = flag_serialized;
	return result;
}

Writes writesJournal(uint64_t journal_info_begin, uint64_t journal_begin, Writes const& journal)
{
	Writes result;

	result[journal_info_begin] = Hpp::uInt64ToByteV(journal_begin);

	if (!journal.empty()) {
		Hpp::ByteV journal_srz;
		for (Writes::const_iterator journal_it = journal.begin();
		     journal_it != journal.end();
		     ++ journal_it) {
			uint64_t begin = journal_it->first;
			Hpp::ByteV const& data = journal_it->second;
			journal_srz += Hpp::uInt64ToByteV(begin);
			journal_srz.push_back(rand() % 0x80 + 0x80);
			journal_srz += Hpp::uInt32ToByteV(data.size());
			journal_srz += data;
		}

		result[journal_begin] = Hpp::uInt64ToByteV(journal_srz.size());
		result[journal_begin + 8] = journal_srz;
	}

	return result;
}
