#ifndef NODES_SYMLINK_H
#define NODES_SYMLINK_H

#include "node.h"

#include <hpp/path.h>

namespace Nodes
{

class Symlink : public Node
{

public:

	Symlink(void);
	Symlink(Hpp::Path const& path);
	Symlink(Hpp::ByteV const& serialized);

private:

	Hpp::Path path;

	// Virtual functions, needed by superclass Node
	virtual void serialize(Hpp::ByteV& result) const;
	inline virtual Type getType(void) const { return TYPE_SYMLINK; }
	inline virtual Children getNonUniqueChildren(void) const { return Children(); }

};

}

#endif
