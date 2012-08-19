#ifndef ARCHIVER_H
#define ARCHIVER_H

#include "useroptions.h"
#include "archive.h"

#include <hpp/path.h>
#include <ostream>

class Archiver
{

public:

	// If password protection is needed, then give non-empty password.
	Archiver(Hpp::Path const& path, std::string const& password, bool create_if_does_not_exist, Useroptions const& useroptions);

	// Prints debug information to standard output
	void printDebugInformation(std::ostream* strm);

	// Archive modification functions
	void put(Paths const& sources, Hpp::Path const& dest);
	void remove(Paths const& paths);
	void snapshot(std::string const& snapshot, Paths const& sources);
	void createNewFolders(Paths const& paths, Nodes::FsMetadata const& fsmetadata);

	// Archive query/and get functions
	void get(Paths const& sources, Hpp::Path const& dest);
	void list(Hpp::Path const& path, std::ostream* strm);

	// Write possible interrupted journal and clean possible orphans.
	void fixPossibleErrors(void);

	// Optimizes archive. This means sorting
	// metadata, filling empty gaps in arrays, etc.
	void optimize(void);

	// Verfies everything is okay
	void verify(void);

private:

	Archive archive;

	void recursivelyPrintChildren(Hpp::ByteV const& node_hash, std::string const& indent, std::ostream* strm);

};

#endif
