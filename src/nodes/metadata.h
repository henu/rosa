#ifndef NODES_METADATA_H
#define NODES_METADATA_H

#include "../options.h"

#include <hpp/cast.h>
#include <hpp/bytev.h>
#include <hpp/assert.h>
#include <hpp/random.h>
#include <ostream>

namespace Nodes
{

struct Metadata
{
	static size_t const ENTRY_SIZE = 80;

	bool empty;
	Hpp::ByteV hash;
	uint32_t refs;
	// This points to the beginning of data entry, i.e. to its header.
	uint64_t data_loc;
	uint32_t data_size_uncompressed;

	inline Metadata(void) :
	empty(true),
	refs(0),
	data_loc(0),
	data_size_uncompressed(0)
	{
	}

	inline Metadata(Hpp::ByteV const& serialized) :
	refs(0),
	data_loc(0),
	data_size_uncompressed(0)
	{
		empty = serialized[0] >= 128;
		if (!empty) {
			HppAssert(serialized.size() == ENTRY_SIZE, "Invalid serialized size!");
			hash.insert(hash.end(), serialized.begin() + 1, serialized.begin() + 1 + NODE_HASH_SIZE);
			refs = Hpp::cStrToUInt(&serialized[1 + NODE_HASH_SIZE], 3);
			data_loc = Hpp::cStrToUInt64(&serialized[1 + NODE_HASH_SIZE + 3]);
			data_size_uncompressed = Hpp::cStrToUInt32(&serialized[1 + NODE_HASH_SIZE + 11]);
		}
	}

	inline Hpp::ByteV serialize(void) const
	{
		Hpp::ByteV result;
		if (empty) {
			result.reserve(1);
			result.push_back(Hpp::randomInt(128, 255));
		} else {
			result.reserve(ENTRY_SIZE);
			result.push_back(Hpp::randomInt(0, 127));
			result += hash;
			result += Hpp::uIntToByteV(refs, 3);
			result += Hpp::uInt64ToByteV(data_loc);
			result += Hpp::uInt32ToByteV(data_size_uncompressed);
			HppAssert(result.size() == ENTRY_SIZE, "Invalid serialized size!");
		}
		return result;
	}

	// For sorting
	inline bool operator<(Metadata const& metadata) const
	{
		return hash < metadata.hash;
	}
};

inline std::ostream& operator<<(std::ostream& strm, Metadata const& metadata)
{
	if (metadata.empty) {
		strm << "<empty>";
	} else {
		strm << Hpp::byteVToHexV(metadata.hash) << " (refs: " << metadata.refs << ", data loc: " << metadata.data_loc << ", data size: " << metadata.data_size_uncompressed << ")";
	}
	return strm;
}

}

#endif
