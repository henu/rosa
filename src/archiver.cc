#include "archiver.h"

#include "nodes/folder.h"
#include "exceptions/alreadyexists.h"

Archiver::Archiver(Hpp::Path const& path, std::string const& password, bool create_if_does_not_exist, Useroptions const& useroptions) :
archive(useroptions)
{
	if (path.exists()) {
		archive.open(path, password);
	} else {
		if (!create_if_does_not_exist) {
			throw Hpp::Exception("Archive \"" + path.toString(true) + "\" does not exist!");
		}
		archive.create(path, password);
	}
}

void Archiver::printDebugInformation(std::ostream* strm)
{
	(*strm) << "Password protected: ";
	if (archive.isPasswordProtected()) (*strm) << "Yes";
	else (*strm) << "No";
	(*strm) << std::endl;

	if (archive.isPasswordProtected()) {
		(*strm) << "  * Password verifier: " << Hpp::byteVToHexV(archive.getPasswordVerifier()) << std::endl;
	}

	(*strm) << "Root node: " << Hpp::byteVToHexV(archive.getRootReference()) << std::endl;

	(*strm) << "Number of nodes: " << archive.getNumOfNodes() << std::endl;
	(*strm) << "Begin of searchtree: " << archive.getBeginOfSearchtree() << std::endl;

	(*strm) << "End of data section: " << archive.getDataSectionEnd() << std::endl;

	(*strm) << "Journal: ";
	if (archive.getJournalFlag()) (*strm) << "Yes";
	else (*strm) << "No";
	(*strm) << std::endl;

	if (archive.getJournalFlag()) {
		(*strm) << "  * Location: " << archive.getJournalLocation() << std::endl;
	}

	(*strm) << "Possible orphan nodes: ";
	if (archive.getOrphanNodesFlag()) (*strm) << "Yes";
	else (*strm) << "No";
	(*strm) << std::endl;

	(*strm) << "Metadata:" << std::endl;
	for (size_t metadata_ofs = 0;
	     metadata_ofs < archive.getNumOfNodes();
	     ++ metadata_ofs) {
		Nodes::Metadata metadata = archive.getMetadata(metadata_ofs);
		(*strm) << "  " << metadata_ofs << " " << metadata << std::endl;
	}

	(*strm) << "Data entries:" << std::endl;
	for (size_t dataentries_ofs = archive.getDataSectionBegin();
	      dataentries_ofs < archive.getDataSectionEnd();
	      dataentries_ofs = archive.getNextDataentry(dataentries_ofs)) {
		Nodes::Dataentry de = archive.getDataentry(dataentries_ofs, false);
		(*strm) << "  " << dataentries_ofs << " " << de.size;
		if (de.empty) {
			(*strm) << " (empty)";
		} else {
			switch (de.type) {
			case Nodes::TYPE_FILE:
				(*strm) << " (file)";
				break;
			case Nodes::TYPE_FOLDER:
				(*strm) << " (folder)";
				break;
			case Nodes::TYPE_SYMLINK:
				(*strm) << " (symlink)";
				break;
			case Nodes::TYPE_DATABLOCK:
				(*strm) << " (datablock)";
				break;
			}
		}
		(*strm) << std::endl;
	}

	(*strm) << "Directory structure:" << std::endl;
	(*strm) << "* <root>" << std::endl;
	recursivelyPrintChildren(archive.getRootReference(), "", strm);

}

void Archiver::put(Paths const& src, Hpp::Path const& dest)
{
	archive.put(src, dest);
}

void Archiver::createNewFolders(Paths const& paths, Nodes::FsMetadata const& fsmetadata)
{
	archive.createNewFolders(paths, fsmetadata);
}

void Archiver::get(Paths const& sources, Hpp::Path const& dest)
{
	archive.get(sources, dest);
}

void Archiver::list(Hpp::Path const& path, std::ostream* strm)
{
	archive.list(path, strm);
}

void Archiver::remove(Paths const& paths)
{
	archive.remove(paths);
}

void Archiver::snapshot(std::string const& snapshot, Paths const& sources)
{
// TODO: In future, use some asking system to tell that if folder already exists, then do not create it!
	Hpp::Path snapshot_path = Hpp::Path("/") / snapshot;
	try {
		Nodes::FsMetadata fsmetadata;
		fsmetadata.readFromCurrentEnvironment();
		archive.createNewFolders(Paths(1, snapshot_path), fsmetadata);
	}
	catch (Exceptions::AlreadyExists) {
	}

	archive.put(sources, snapshot_path);
}

void Archiver::fixPossibleErrors(void)
{
	archive.finishPossibleInterruptedJournal();
// TODO: Remove possible orphans!
}

void Archiver::optimize(void)
{
	archive.optimizeMetadata();
}

void Archiver::verify(void)
{
	archive.verifyDataentriesAreValid(true);
	archive.verifyNoDoubleMetadatas(true);
	archive.verifyReferences(true);
	archive.verifyMetadatas(true);
	archive.verifyRootNodeExists(true);
}

void Archiver::recursivelyPrintChildren(Hpp::ByteV const& node_hash, std::string const& indent, std::ostream* strm)
{
	// Get this node as Folder
	Nodes::Folder folder(archive.getNodeData(node_hash));

	for (std::string child = folder.getFirstChild();
	     child != "";
	     child = folder.getNextChild(child)) {
		Nodes::FsType child_type = folder.getChildType(child);

		(*strm) << indent;

		// If this is last child, then print different kind of junction
		std::string child_indent = indent;
		if (folder.getNextChild(child) == "") {
			(*strm) << "`-";
			child_indent += "  ";
		} else {
			(*strm) << "+-";
			child_indent += "| ";
		}

		(*strm) << "* " << child << std::endl;

		if (child_type == Nodes::FSTYPE_FOLDER) {
			recursivelyPrintChildren(folder.getChildHash(child), child_indent, strm);
		}
	}
}
