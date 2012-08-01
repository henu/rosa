#include "folder.h"

#include "../options.h"

#include <hpp/cast.h>
#include <hpp/serialize.h>

namespace Nodes
{

Folder::Folder(void)
{
}

Folder::Folder(Hpp::ByteV const& serialized)
{
	Hpp::ByteV::const_iterator serialized_it = serialized.begin();

	try {
		size_t children_size = Hpp::deserializeUInt32(serialized_it, serialized.end());
		while (children.size() < children_size) {
			Child new_child;
			std::string child_name = Hpp::deserializeString(serialized_it, serialized.end(), 2);
			new_child.type = (FsType)(Hpp::deserializeUInt8(serialized_it, serialized.end()));
			new_child.hash = Hpp::deserializeByteV(serialized_it, serialized.end(), NODE_HASH_SIZE);
			new_child.fsmetadata = FsMetadata(serialized_it, serialized.end());
			if (children.find(child_name) != children.end()) {
				throw 0xbeef;
			}
			children[child_name] = new_child;
		}
	}
	catch ( ... ) {
		throw Hpp::Exception("Folder data corrupted!");
	}

}

void Folder::setChild(std::string const& child_name, FsType child_type, Hpp::ByteV child_hash, FsMetadata const& child_fsmetadata)
{
	HppAssert(child_hash.size() == NODE_HASH_SIZE, "Invalid hash size!");
	Child new_child;
	new_child.type = child_type;
	new_child.hash = child_hash;
	new_child.fsmetadata = child_fsmetadata;
	children[child_name] = new_child;
	markDataChanged();
}

void Folder::addChildren(Children const& children)
{
	for (Children::const_iterator children_it = children.begin();
	     children_it != children.end();
	     ++ children_it) {
		std::string const& child_name = children_it->first;
		Child const& child = children_it->second;
		HppAssert(child.hash.size() == NODE_HASH_SIZE, "Invalid hash size!");
		this->children[child_name] = child;
	}
	markDataChanged();
}

void Folder::removeChild(std::string const& child_name)
{
	if (children.erase(child_name) == 0) {
		throw Hpp::Exception("Folder does not have a child named \"" + child_name + "\", so unable to remove!");
	}
}

bool Folder::hasChild(std::string const& child_name) const
{
	return children.find(child_name) != children.end();
}

FsType Folder::getChildType(std::string const& child_name) const
{
	HppAssert(hasChild(child_name), "No child with that name found!");
	return children.find(child_name)->second.type;
}

FsMetadata Folder::getChildFsMetadata(std::string const& child_name) const
{
	HppAssert(hasChild(child_name), "No child with that name found!");
	return children.find(child_name)->second.fsmetadata;
}

Hpp::ByteV Folder::getChildHash(std::string const& child_name) const
{
	HppAssert(hasChild(child_name), "No child with that name found!");
	return children.find(child_name)->second.hash;
}

std::string Folder::getFirstChild(void) const
{
	if (children.empty()) {
		return "";
	}
	return children.begin()->first;
}

std::string Folder::getNextChild(std::string const& child_name) const
{
	Children::const_iterator children_find = children.upper_bound(child_name);
	if (children_find == children.end()) {
		return "";
	}
	return children_find->first;
}

void Folder::serialize(Hpp::ByteV& result) const
{
	result += Hpp::uInt32ToByteV(children.size());
	for (Children::const_iterator children_it = children.begin();
	     children_it != children.end();
	     ++ children_it) {
		std::string const& name = children_it->first;
		Child const& child = children_it->second;
		// Serialize
		Hpp::serializeString(result, name, 2);
		result.push_back(child.type);
		result += child.hash;
		result += child.fsmetadata.serialize();
	}
}

Nodes::Children Folder::getNonUniqueChildren(void) const
{
	Nodes::Children result;
	result.reserve(children.size());
	for (Children::const_iterator children_it = children.begin();
	     children_it != children.end();
	     ++ children_it) {
		Child const& child = children_it->second;
		Nodes::Child new_nchild;
		new_nchild.hash = child.hash;
		switch (child.type) {
		case FSTYPE_FOLDER:
			new_nchild.type = TYPE_FOLDER;
			break;
		case FSTYPE_FILE:
			new_nchild.type = TYPE_FILE;
			break;
		case FSTYPE_SYMLINK:
			new_nchild.type = TYPE_SYMLINK;
			break;
		}
		result.push_back(new_nchild);
	}
	return result;
}

}
