#include "node.h"

#include <hpp/exception.h>
#include <hpp/sha512hasher.h>
#include <algorithm>

namespace Nodes
{

Hpp::ByteV Node::getData(void)
{
	if (data.empty()) {
		serialize(data);
	}
	return data;
}

Hpp::ByteV Node::getHash(void)
{
	// If hash is not calculated, then do it now
	if (hash.empty()) {
		// If data is not got, then got it now
		if (data.empty()) {
			serialize(data);
		}
		// Get also type of Node, so Nodes with same
		// data, but different type get different hash.
		Nodes::Type type = getType();
		// Do hashing
		Hpp::Sha512Hasher hasher;
		hasher.addData(data);
		hasher.addData(Hpp::ByteV(1, type));
		hasher.getHash(hash);
	}
	return hash;
}

Children Node::getChildrenNodes(void) const
{
	Children children = getNonUniqueChildren();
	std::sort(children.begin(), children.end());
	Children::iterator new_end = std::unique(children.begin(), children.end());
	children.erase(new_end, children.end());
	return children;
}

}
