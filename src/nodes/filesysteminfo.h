#ifndef NODES_FILESYSTEMINFO_H
#define NODES_FILESYSTEMINFO_H

#include <hpp/path.h>
#include <hpp/bytev.h>
#include <hpp/serialize.h>
#include <hpp/time.h>
#include <map>
#include <string>

namespace Nodes
{

	enum FsType {
		FSTYPE_FOLDER = 0,
		FSTYPE_FILE = 1,
		FSTYPE_SYMLINK = 2
	};

	class FsMetadata
	{

	public:

		inline FsMetadata(void)
		{
			Hpp::Time now = Hpp::now();
			pairs["crtime"] = Hpp::sizeToStr(now.getSeconds());
			pairs["crtime_nsec"] = Hpp::sizeToStr(now.getNanoseconds());
			pairs["mtime"] = Hpp::sizeToStr(now.getSeconds());
			pairs["mtime_nsec"] = Hpp::sizeToStr(now.getNanoseconds());
		}
		inline FsMetadata(Hpp::Path const& path)
		{
			// Read metadata from given target
			Hpp::Path::Metadata metadata = path.getMetadata();

			// User permissions
			if (!metadata.owner.empty()) pairs["user"] = metadata.owner;
			if (!metadata.group.empty()) pairs["group"] = metadata.group;

			// Creation and modification time
			if (metadata.created.getSeconds() != 0) {
				pairs["crtime"] = Hpp::sizeToStr(metadata.created.getSeconds());
				pairs["crtime_nsec"] = Hpp::sizeToStr(metadata.created.getNanoseconds());
			}
			if (metadata.modified.getSeconds() != 0) {
				pairs["mtime"] = Hpp::sizeToStr(metadata.modified.getSeconds());
				pairs["mtime_nsec"] = Hpp::sizeToStr(metadata.modified.getNanoseconds());
			}
		}
		inline FsMetadata(Hpp::ByteV::const_iterator& serialized_it, Hpp::ByteV::const_iterator const& serialized_end)
		{
			uint16_t pairs_size = Hpp::deserializeUInt16(serialized_it, serialized_end);
			for (size_t pair_id = 0; pair_id < pairs_size; ++ pair_id) {
				std::string key = Hpp::deserializeString(serialized_it, serialized_end, 1);
				std::string value = Hpp::deserializeString(serialized_it, serialized_end, 2);
				pairs[key] = value;
			}
		}

		Hpp::ByteV serialize(void) const
		{
			Hpp::ByteV result;
			HppAssert(pairs.size() <= 0xffff, "Too many pairs!");
			result += Hpp::uInt16ToByteV(pairs.size());
			for (Pairs::const_iterator pairs_it = pairs.begin();
			     pairs_it != pairs.end();
			     ++ pairs_it) {
				std::string const& key = pairs_it->first;
				std::string const& value = pairs_it->second;
				HppAssert(key.size() <= 0xff, "Too long key!");
				HppAssert(value.size() <= 0xffff, "Too long value!");
				Hpp::serializeString(result, key, 1);
				Hpp::serializeString(result, value, 2);
			}
			return result;
		}

	private:

		typedef std::map< std::string, std::string > Pairs;

		Pairs pairs;

	};

}

#endif
