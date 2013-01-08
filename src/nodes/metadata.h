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
	static size_t const ENTRY_SIZE = 103;
	static uint64_t const NULL_REF = uint64_t(-1);

	Hpp::ByteV hash;
	uint32_t refs;
	// Binary search tree variables
	uint64_t parent;
	uint64_t child_small;
	uint64_t child_big;
	// This points to the beginning of data entry, i.e. to its header.
	uint64_t data_loc;
// TODO: Is this useless?
	uint32_t data_size_uncompressed;

	inline Metadata(void) :
	refs(0),
	parent(NULL_REF),
	child_small(NULL_REF),
	child_big(NULL_REF),
	data_loc(0),
	data_size_uncompressed(0)
	{
	}

	inline Metadata(Hpp::ByteV const& serialized)
	{
		HppAssert(serialized.size() == ENTRY_SIZE, "Invalid serialized size!");

		hash.insert(hash.end(), serialized.begin(), serialized.begin() + NODE_HASH_SIZE);
// TODO: Would it be a good idea to use 4 bytes? With 3 bytes, for example only 16 million empty directories/files are supported!
		refs = Hpp::cStrToUInt(&serialized[NODE_HASH_SIZE], 3);

		parent = Hpp::cStrToUInt64(&serialized[NODE_HASH_SIZE + 3]);
		child_small = Hpp::cStrToUInt64(&serialized[NODE_HASH_SIZE + 11]);
		child_big = Hpp::cStrToUInt64(&serialized[NODE_HASH_SIZE + 19]);

		data_loc = Hpp::cStrToUInt64(&serialized[NODE_HASH_SIZE + 27]);
		data_size_uncompressed = Hpp::cStrToUInt32(&serialized[NODE_HASH_SIZE + 35]);
	}

	inline Hpp::ByteV serialize(void) const
	{
		Hpp::ByteV result;
		result.reserve(ENTRY_SIZE);

		result += hash;
		result += Hpp::uIntToByteV(refs, 3);

		result += Hpp::uInt64ToByteV(parent);
		result += Hpp::uInt64ToByteV(child_small);
		result += Hpp::uInt64ToByteV(child_big);

		result += Hpp::uInt64ToByteV(data_loc);
		result += Hpp::uInt32ToByteV(data_size_uncompressed);

		HppAssert(result.size() == ENTRY_SIZE, "Invalid serialized size!");

		return result;
	}

	// For sorting
	inline bool operator<(Metadata const& metadata) const
	{
		return hash < metadata.hash;
	}
	inline bool operator==(Metadata const& metadata) const
	{
		return hash == metadata.hash;
	}

	inline static std::string searchtreeRefToString(uint64_t ref)
	{
		if (ref == NULL_REF) return "null";
		return Hpp::sizeToStr(ref);
	}

};

inline std::ostream& operator<<(std::ostream& strm, Metadata const& metadata)
{
	strm << Hpp::byteVToHexV(metadata.hash) << " (refs: " << metadata.refs << ", st.parent: " << Metadata::searchtreeRefToString(metadata.parent) << ", st.child_s: " << Metadata::searchtreeRefToString(metadata.child_small) << ", st.child_b: " << Metadata::searchtreeRefToString(metadata.child_big) << ", data loc: " << metadata.data_loc << ", data size: " << metadata.data_size_uncompressed << ")";
	return strm;
}

}

#endif
