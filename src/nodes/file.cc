#include "file.h"

#include "../options.h"

#include <hpp/cast.h>
#include <hpp/serialize.h>

namespace Nodes
{

File::File(void)
{
}

File::File(Hpp::ByteV const& serialized)
{
	Hpp::ByteV::const_iterator serialized_it = serialized.begin();

	uint32_t datablocks_size;

	// Check if old or new method should be used when deserializing this
	if (serialized.size() % (NODE_HASH_SIZE + 4) == 0) {
		datablocks_size = serialized.size() / (NODE_HASH_SIZE + 4);
	} else {
		datablocks_size = Hpp::deserializeUInt32(serialized_it, serialized.end());
		if (datablocks_size != (serialized.size() - 4) / (NODE_HASH_SIZE + 4)) {
			throw Hpp::Exception("File node is corrupted!");
		}
	}

	datablocks.reserve(datablocks_size);
	uint64_t last_datablock_end = 0;
	while (datablocks.size() < datablocks_size) {
		Datablock new_datablock;
		new_datablock.begin = last_datablock_end;
		new_datablock.size = Hpp::deserializeUInt32(serialized_it, serialized.end());
		new_datablock.hash = Hpp::deserializeByteV(serialized_it, serialized.end(), NODE_HASH_SIZE);
		datablocks.push_back(new_datablock);
		last_datablock_end += new_datablock.size;
	}
}

void File::addDatablock(Hpp::ByteV const& hash, uint32_t size)
{
	uint64_t last_datablock_end;
	if (datablocks.empty()) {
		last_datablock_end = 0;
	} else {
		last_datablock_end = datablocks.back().begin + datablocks.back().size;
	}
	Datablock new_datablock;
	new_datablock.begin = last_datablock_end;
	new_datablock.size = size;
	new_datablock.hash = hash;
	datablocks.push_back(new_datablock);
}

void File::serialize(Hpp::ByteV& result) const
{
	for (Datablocks::const_iterator datablocks_it = datablocks.begin();
	     datablocks_it != datablocks.end();
	     ++ datablocks_it) {
		Datablock const& datablock = *datablocks_it;
		result += Hpp::uInt32ToByteV(datablock.size);
		result += datablock.hash;
	}
}

Children File::getNonUniqueChildren(void) const
{
	Children result;
	result.reserve(datablocks.size());
	for (Datablocks::const_iterator datablocks_it = datablocks.begin();
	     datablocks_it != datablocks.end();
	     ++ datablocks_it) {
		Child child;
		child.hash = datablocks_it->hash;
		child.type = TYPE_DATABLOCK;
		result.push_back(child);
	}
	return result;
}

}
