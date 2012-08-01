#include "archiver.h"

#include "nodes/folder.h"

#include <iostream>

Archiver::Archiver(Hpp::Path const& path, std::string const& password, bool create_if_does_not_exist)
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

void Archiver::printDebugInformation(void)
{
	std::cout << "Password protected: ";
	if (archive.isPasswordProtected()) std::cout << "Yes";
	else std::cout << "No";
	std::cout << std::endl;

	if (archive.isPasswordProtected()) {
		std::cout << "  * Password verifier: " << Hpp::byteVToHexV(archive.getPasswordVerifier()) << std::endl;
	}

	std::cout << "Root node: " << Hpp::byteVToHexV(archive.getRootReference()) << std::endl;

	std::cout << "Space allocated for metadata (sorted/unsorted): " << archive.getSortedMetadataAllocation() << "/" << archive.getUnsortedMetadataAllocation() << std::endl;

	std::cout << "End of data section: " << archive.getDataSectionEnd() << std::endl;

	std::cout << "Journal: ";
	if (archive.getJournalFlag()) std::cout << "Yes";
	else std::cout << "No";
	std::cout << std::endl;

	if (archive.getJournalFlag()) {
		std::cout << "  * Location: " << archive.getJournalLocation() << std::endl;
	}

	std::cout << "Possible orphan nodes: ";
	if (archive.getOrphanNodesFlag()) std::cout << "Yes";
	else std::cout << "No";
	std::cout << std::endl;

	std::cout << "Sorted metadata:" << std::endl;
	for (size_t metadata_ofs = 0;
	     metadata_ofs < archive.getSortedMetadataAllocation();
	     ++ metadata_ofs) {
		Nodes::Metadata metadata = archive.getSortedMetadata(metadata_ofs);
		std::cout << "  " << metadata_ofs << " " << metadata << std::endl;
	}

	std::cout << "Unsorted metadata:" << std::endl;
	for (size_t metadata_ofs = 0;
	     metadata_ofs < archive.getUnsortedMetadataAllocation();
	     ++ metadata_ofs) {
		Nodes::Metadata metadata = archive.getUnsortedMetadata(metadata_ofs);
		std::cout << "  " << metadata_ofs << " " << metadata << std::endl;
	}

	std::cout << "Data entries:" << std::endl;
	for (size_t dataentries_ofs = archive.getDataSectionBegin();
	      dataentries_ofs < archive.getDataSectionEnd();
	      dataentries_ofs = archive.getNextDataEntry(dataentries_ofs)) {
		Nodes::DataEntry de = archive.getDataEntry(dataentries_ofs, false);
		std::cout << "  " << dataentries_ofs << " " << de.size;
		if (de.empty) {
			std::cout << " (empty)";
		} else {
			switch (de.type) {
			case Nodes::TYPE_FILE:
				std::cout << " (file)";
				break;
			case Nodes::TYPE_FOLDER:
				std::cout << " (folder)";
				break;
			case Nodes::TYPE_SYMLINK:
				std::cout << " (symlink)";
				break;
			case Nodes::TYPE_DATABLOCK:
				std::cout << " (datablock)";
				break;
			}
		}
		std::cout << std::endl;
	}

	std::cout << "Directory structure:" << std::endl;
	std::cout << "* <root>" << std::endl;
	recursivelyPrintChildren(archive.getRootReference(), "");

}

void Archiver::put(Paths const& src, Hpp::Path const& dest, std::ostream* strm)
{
	archive.put(src, dest, strm);
}

void Archiver::get(Paths const& sources, Hpp::Path const& dest, std::ostream* strm)
{
	archive.get(sources, dest, strm);
}

void Archiver::remove(Paths const& paths, std::ostream* strm)
{
	archive.remove(paths, strm);
}

void Archiver::snapshot(std::string const& snapshot, Paths const& sources, std::ostream* strm)
{
// TODO: In future, use some asking system to tell that if folder already exists, then do not create it!
	Hpp::Path snapshot_path = Hpp::Path("/") / snapshot;
	try {
		archive.createNewFolder(snapshot_path, Nodes::FsMetadata());
	}
	catch (Hpp::Exception) {
	}

	archive.put(sources, snapshot_path, strm);
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

void Archiver::recursivelyPrintChildren(Hpp::ByteV const& node_hash, std::string const& indent)
{
	// Get this node as Folder
	Nodes::Folder folder(archive.getNodeData(node_hash));

	for (std::string child = folder.getFirstChild();
	     child != "";
	     child = folder.getNextChild(child)) {
		Nodes::FsType child_type = folder.getChildType(child);

		std::cout << indent;

		// If this is last child, then print different kind of junction
		std::string child_indent = indent;
		if (folder.getNextChild(child) == "") {
			std::cout << "`-";
			child_indent += "  ";
		} else {
			std::cout << "+-";
			child_indent += "| ";
		}

		std::cout << "* " << child << std::endl;

		if (child_type == Nodes::FSTYPE_FOLDER) {
			recursivelyPrintChildren(folder.getChildHash(child), child_indent);
		}
	}
}
