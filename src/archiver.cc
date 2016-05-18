#include "archiver.h"

#include "nodes/folder.h"
#include "exceptions/alreadyexists.h"

Archiver::Archiver(Hpp::Path const& path, std::string const& password,
                   bool create_if_does_not_exist, bool read_write_mode,
                   Useroptions const& useroptions) :
archive(read_write_mode, useroptions)
{
	if (path.exists()) {
		archive.open(path, password);
	} else {
		if (!create_if_does_not_exist) {
			throw Hpp::Exception("Archive \"" + path.toString(true) + "\" does not exist!");
		}
		archive.create(path, password);
	}

	// Journal is always fixed. In read only
	// mode, it is fixed to read cache.
	archive.finishPossibleInterruptedJournal();
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

	size_t dataarea_size = archive.getDataareaSize();
	size_t empty_bytes = archive.getEmptyBytesAtDataarea();

	(*strm) << "Size of data area: " << dataarea_size << std::endl;
	(*strm) << "Actual bytes at data area: " << (dataarea_size - empty_bytes) << std::endl;
	(*strm) << "Empty bytes at data area: " << empty_bytes << std::endl;
	(*strm) << "Percent of empty bytes at data area: " << int(100 * (double(empty_bytes) / dataarea_size) + 0.5) << std::endl;

	(*strm) << "Begin of searchtree: " << archive.getBeginOfSearchtree() << std::endl;

	Archive::SearchtreeDepthAnalysis stda = archive.getSearchtreeDepths();
	(*strm) << "Searchtree depth analysis:";
	for (Archive::SearchtreeDepthAnalysis::const_iterator stda_it = stda.begin();
	     stda_it != stda.end();
	     ++ stda_it) {
		(*strm) << " " << stda_it->first << "/" << stda_it->second;
	}
	(*strm) << std::endl;

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
	archive.shrinkFileToMinimumPossible();
}

void Archiver::createNewFolders(Paths const& paths, Nodes::FsMetadata const& fsmetadata)
{
	archive.createNewFolders(paths, fsmetadata);
	archive.shrinkFileToMinimumPossible();
}

void Archiver::get(Paths const& sources, Hpp::Path const& dest)
{
	archive.get(sources, dest);
}

void Archiver::list(Hpp::Path const& path, std::ostream* strm)
{
	archive.list(path, strm);
}

void Archiver::removePossibleOrphans()
{
	if (archive.getOrphanNodesFlag()) {
		archive.removePossibleOrphans();
	}
}

void Archiver::remove(Paths const& paths)
{
	archive.remove(paths);
	archive.shrinkFileToMinimumPossible();
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
	archive.shrinkFileToMinimumPossible();
}

void Archiver::optimize(bool remove_empty_dataentries)
{
	archive.optimizeMetadata();
	if (remove_empty_dataentries) {
		archive.removeEmptyDataentries();
	}
	archive.shrinkFileToMinimumPossible();
}

void Archiver::verify(Useroptions const& useroptions, bool fix_errors)
{
	if (useroptions.verbose) *useroptions.verbose << "Verifying dataentries are valid..." << std::endl;
	archive.verifyDataentriesAreValid(true);

	if (useroptions.verbose) *useroptions.verbose << "Verifying No double metadatas..." << std::endl;
	archive.verifyNoDoubleMetadatas(true);

	if (useroptions.verbose) *useroptions.verbose << "Verifying metadatas..." << std::endl;
	archive.verifyMetadatas(true);

	if (useroptions.verbose) *useroptions.verbose << "Verifying root node exists..." << std::endl;
	archive.verifyRootNodeExists(true);

	archive.verifyReferences(true, fix_errors);

	if (useroptions.verbose) *useroptions.verbose << "Done!" << std::endl;
}

void Archiver::fix(void)
{
	archive.removeCorruptedNodesAndFixDataarea();
	archive.verifyReferences(true, true);
	archive.rebuildTree();
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
