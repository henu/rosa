#ifndef NODES_FILESYSTEMINFO_H
#define NODES_FILESYSTEMINFO_H

#include <hpp/path.h>
#include <hpp/bytev.h>

namespace Nodes
{

	enum FsType {
		FSTYPE_FOLDER = 0,
		FSTYPE_FILE = 1,
		FSTYPE_SYMLINK = 2
	};

// TODO: Implement this!
	struct FsMetadata
	{
		inline FsMetadata(void)
		{
		}
		inline FsMetadata(Hpp::Path const& path)
		{
(void)path;
		}
		inline FsMetadata(Hpp::ByteV::const_iterator& serialized_it, Hpp::ByteV::const_iterator const& serialized_end)
		{
(void)serialized_it;
(void)serialized_end;
		}

		Hpp::ByteV serialize(void) const
		{
			Hpp::ByteV result;
			return result;
		}
	};

}

#endif
