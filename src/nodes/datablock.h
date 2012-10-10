#ifndef NODES_DATABLOCK_H
#define NODES_DATABLOCK_H

#include "node.h"

#include <hpp/bytev.h>

namespace Nodes
{

class Datablock : public Node
{

public:

	Datablock(void);
	// This constructor is used both when constructed from
	// source file and when serialized from archive.
	Datablock(Hpp::ByteV const& serialized);
	virtual inline ~Datablock(void) { }

private:

	Hpp::ByteV data;

	// Virtual functions, needed by superclass Node
	virtual void serialize(Hpp::ByteV& result) const;
	inline virtual Type getType(void) const { return TYPE_DATABLOCK; }
	inline virtual Children getNonUniqueChildren(void) const { return Children(); }

};

}

#endif
