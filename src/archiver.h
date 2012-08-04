#ifndef ARCHIVER_H
#define ARCHIVER_H

#include "archive.h"

#include <hpp/path.h>

class Archiver
{

public:

	// If password protection is needed, then give non-empty password.
	Archiver(Hpp::Path const& path, std::string const& password, bool create_if_does_not_exist);

	// Prints debug information to standard output
	void printDebugInformation(void);

	// Archive modification functions
	void put(Paths const& sources, Hpp::Path const& dest, std::ostream* strm);
	void remove(Paths const& paths, std::ostream* strm);
	void snapshot(std::string const& snapshot, Paths const& sources, std::ostream* strm);
	void createNewFolders(Paths const& paths, Nodes::FsMetadata const& fsmetadata, std::ostream* strm);

	// Archive query/and get functions
	void get(Paths const& sources, Hpp::Path const& dest, std::ostream* strm);

	// Write possible interrupted journal and clean possible orphans.
	void fixPossibleErrors(void);

	// Optimizes archive. This means sorting
	// metadata, filling empty gaps in arrays, etc.
	void optimize(void);

private:

	Archive archive;

	void recursivelyPrintChildren(Hpp::ByteV const& node_hash, std::string const& indent);

};

#endif
