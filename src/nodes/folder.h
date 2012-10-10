#ifndef NODES_FOLDER_H
#define NODES_FOLDER_H

#include "node.h"
#include "filesysteminfo.h"

#include <hpp/bytev.h>
#include <map>
#include <vector>

namespace Nodes
{

class Folder : public Node
{

public:

	struct Child
	{
		FsType type;
		Hpp::ByteV hash;
		FsMetadata fsmetadata;
	};
	typedef std::map< std::string, Child > Children;

	Folder(void);
	Folder(Hpp::ByteV const& serialized);
	virtual inline ~Folder(void) { }

	// Child modifiers. addChildren will not remove old ones,
	// but it will replace them, if same names are given.
	void setChild(std::string const& child_name, Child const& child);
	void setChild(std::string const& child_name, FsType child_type, Hpp::ByteV child_hash, FsMetadata const& child_fsmetadata);
	void addChildren(Children const& children);
	void removeChild(std::string const& child_name);

	// Child getters
	bool hasChild(std::string const& child_name) const;
	FsType getChildType(std::string const& child_name) const;
	FsMetadata getChildFsMetadata(std::string const& child_name) const;
	Hpp::ByteV getChildHash(std::string const& child_name) const;

	// Child iterators. Both functions return empty
	// string if there is no child to return.
	std::string getFirstChild(void) const;
	std::string getNextChild(std::string const& child_name) const;

private:

	Children children;

	// Virtual functions, needed by superclass Node
	virtual void serialize(Hpp::ByteV& result) const;
	inline virtual Type getType(void) const { return TYPE_FOLDER; }
	virtual Nodes::Children getNonUniqueChildren(void) const;

};

typedef std::vector< Folder > Folders;

}

#endif
