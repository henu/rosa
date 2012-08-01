#ifndef NODES_NODE_H
#define NODES_NODE_H

#include "children.h"
#include "type.h"

#include <hpp/bytev.h>

namespace Nodes
{

class Node
{

public:

	Hpp::ByteV getData(void);
	Hpp::ByteV getHash(void);

	// Returns all direct children Nodes. Note, that even
	// if Node really has some child multiple times, here
	// they are already reduced to only one.
	Children getChildrenNodes(void) const;

	// Gets type of node
	virtual Type getType(void) const = 0;

protected:

	// Informs Node, that subclass has updated, and
	// data plus hash needs to be recalculated.
	inline void markDataChanged(void) { data.clear(); hash.clear(); }

private:

	Hpp::ByteV data;
	Hpp::ByteV hash;

	// Asks for new serialization from subclass. Result is already cleared.
	virtual void serialize(Hpp::ByteV& result) const = 0;

	// Returns hash of nodes that are direct children of this
	// Node. These may contain same children multiple times.
	virtual Children getNonUniqueChildren(void) const = 0;

};

}

#endif
