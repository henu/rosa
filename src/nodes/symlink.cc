#include "symlink.h"

#include <hpp/cast.h>
#include <hpp/serialize.h>
#include <hpp/unicodestring.h>

namespace Nodes
{

Symlink::Symlink(void)
{
}

Symlink::Symlink(Hpp::Path const& path) :
path(path)
{
}

Symlink::Symlink(Hpp::ByteV const& serialized)
{
	std::string raw_string((const char*)&serialized[0], serialized.size());

	// If any of first two characters is null byte, or if conversion to
	// UTF8 fails, then this must be deserialized using the old method.
	bool use_old_method = false;
	if (!raw_string.empty() && raw_string[0] == '\0') {
		use_old_method = true;
	} else if (!raw_string.size() >= 2 && raw_string[1] == '\0') {
		use_old_method = true;
	} else {
		try {
			Hpp::UnicodeString unicodestring(raw_string);
		}
		catch ( ... ) {
			use_old_method = true;
		}
	}

	if (use_old_method) {
		Hpp::ByteV::const_iterator serialized_it = serialized.begin();
		path = Hpp::Path(Hpp::deserializeString(serialized_it, serialized.end(), 2));
	} else {
		path = Hpp::Path(raw_string);
	}
}

void Symlink::serialize(Hpp::ByteV& result) const
{
	HppAssert(result.empty(), "Result should be cleared!");
	result += path.toString();
}

}
