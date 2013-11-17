#ifndef NODES_FILE_H
#define NODES_FILE_H

#include "node.h"

#include <hpp/bytev.h>
#include <hpp/assert.h>
#include <vector>

namespace Nodes
{

class File : public Node
{

public:

	struct Datablock
	{
		Hpp::ByteV hash;
		uint64_t begin;
		uint32_t size;
	};

	File(void);
	File(Hpp::ByteV const& serialized);
	virtual inline ~File(void) { }

	// Adds datablock using its hash
	void addDatablock(Hpp::ByteV const& hash, uint32_t size);

	// Datablock iterators
	inline size_t getNumOfDatablocks(void) const { return datablocks.size(); }
	inline Datablock getDatablock(size_t datablock_id) const { HppAssert(datablock_id < datablocks.size(), "Overflow!"); return datablocks[datablock_id]; }

private:

	typedef std::vector< Datablock > Datablocks;

	Datablocks datablocks;

	// Virtual functions, needed by superclass Node
	virtual void serialize(Hpp::ByteV& result) const;
	inline virtual Type getType(void) const { return TYPE_FILE; }
	virtual Children getNonUniqueChildren(void) const;

};

}

#endif
