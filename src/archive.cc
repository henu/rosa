#include "archive.h"

#include "nodes/datablock.h"
#include "nodes/file.h"
#include "nodes/symlink.h"
#include "options.h"

#ifdef ENABLE_PROFILER
#include <hpp/profiler.h>
#endif
#include <hpp/decompressor.h>
#include <hpp/exception.h>
#include <hpp/serialize.h>
#include <hpp/random.h>
#include <hpp/sha256hasher.h>
#include <hpp/sha512hasher.h>
#include <hpp/compressor.h>
#include <cstring>
#include <set>

Archive::Archive(Useroptions const& useroptions) :
useroptions(useroptions),
metas_s_size(0),
metas_us_size(0),
datasec_end(0),
orphan_nodes_exists(false)
{
}

void Archive::open(Hpp::Path const& path, std::string const& password)
{
	closeAndOpenFile(path);

	loadStateFromFile(password);

	HppAssert(verifyDataentriesAreValid(), "Dataentries are broken!");
}

void Archive::create(Hpp::Path const& path, std::string const& password)
{
	closeAndOpenFile(path);

	// Initialize empty archive
	Writes writes;

	// Identifier
	size_t const IDENTIFIER_LEN = strlen(ARCHIVE_IDENTIFIER);
	writes[0] = Hpp::ByteV(ARCHIVE_IDENTIFIER, ARCHIVE_IDENTIFIER + IDENTIFIER_LEN);

	// Version
	writes[IDENTIFIER_LEN] = Hpp::ByteV(1, 0);

	// Crypto flag and possible salt
	Hpp::ByteV salt;
	if (password.empty()) {
		writes[IDENTIFIER_LEN + 1] = Hpp::ByteV(1, 0);
	} else {
		writes[IDENTIFIER_LEN + 1] = Hpp::ByteV(1, 1);
		salt = Hpp::randomSecureData(SALT_SIZE);
		writes[IDENTIFIER_LEN + 2] = salt;
	}

	// This is the end of part that is always
	// written as plain text, so do writes now.
	io.doWrites(writes, true);

	// If password is used, then generate crypto key and password verifier
	if (!password.empty()) {
		crypto_key = generateCryptoKey(password, salt);

		// Inform FileIO about this
		io.enableCrypto(crypto_key);

		// Create new password verifier and write it to the disk.
		crypto_password_verifier = Hpp::randomSecureData(PASSWORD_VERIFIER_SIZE / 2);
		io.doWrites(writesPasswordVerifier());

	}

	io.initAndWriteJournalFlagToFalse();

	io.doWrites(writesJournal(getSectionBegin(SECTION_JOURNAL_INFO), Hpp::randomNBitInt(64), Writes()));

	setOrphanNodesFlag(true);

	// Initialize rest of header with fake root reference and zero metadata
	// amounts. After this, everything is correct, except root reference.
	root_ref = Hpp::ByteV(64, 0);
	metas_s_size = 0;
	metas_us_size = 0;
	datasec_end = getSectionBegin(SECTION_DATA);

	// Inform FileIO about new data end
	io.setEndOfData(datasec_end);

	io.doWrites(writesRootRefAndCounts());

	// Spawn empty Folder node to serve as root node
	Nodes::Folder folder;
	spawnOrGetNode(&folder);
	root_ref = folder.getHash();
	io.doWrites(writesSetNodeRefs(root_ref, 1));
	io.doWrites(writesRootRefAndCounts());

	setOrphanNodesFlag(false);

	// Write to disk
	io.flush();

	HppAssert(verifyReferences(), "Reference counts have failed!");
}

void Archive::put(Paths const& src, Hpp::Path const& dest)
{
	HppAssert(!src.empty(), "No sources!");

	// Force destination path to absolute form
	Hpp::Path dest_abs = dest;
	dest_abs.forceToAbsolute();

	// If destination does not exist, but its parent do, and if there is
	// only one source, then get name from destination when copying source
	bool get_name_from_dest = false;

	// Search for the destination folder
	Nodes::Folders fpath;
	Hpp::Path dest_fixed(dest);
	try {
		fpath = getFoldersToPath(root_ref, dest_abs);
	}
	catch (Hpp::Exception) {
		// Path does not exist. Check if destination has parent
		if (!dest_abs.hasParent()) {
			throw Hpp::Exception("Path does not exist!");
		}
		if (src.size() != 1) {
			throw Hpp::Exception("Unable to put multiple files/dirs to archive under only one name! Did you forgot to create folder \"" + dest.toString() + "\"?");
		}
		// Get folder path
		Hpp::Path dest_parent = dest_abs.getParent();
		fpath = getFoldersToPath(root_ref, dest_parent);
		get_name_from_dest = true;
		dest_fixed = dest_parent;
	}

	// The following operations will create new Nodes,
	// that will be orphans at first. Because of this,
	// the appropriate flag needs to be toggled on.
	bool orphan_nodes_flag_before = getOrphanNodesFlag();
	setOrphanNodesFlag(true);

	Nodes::Folder new_folder = fpath.back();
	Hpp::ByteV root_now;

	if (get_name_from_dest) {
		// Read file hierarchy as Children of Folder
		Nodes::Folder::Children new_children;
// TODO: Ask here what to overwrite/discard/join/etc.!
		readFileHierarchiesAsFolderChildren(new_children, src);

		// Set the only child
		HppAssert(new_children.size() == 1, "There should be exactly one child!");
		new_folder.setChild(dest.getFilename(), new_children[0]);

		root_now = replaceLastFolder(fpath, dest_fixed, new_folder);

	} else {
		// Read file hierarchy as Children of Folder
		Nodes::Folder::Children new_children;
// TODO: Ask here what to overwrite/discard/join/etc.!
		readFileHierarchiesAsFolderChildren(new_children, src);

		new_folder.addChildren(new_children);

		root_now = replaceLastFolder(fpath, dest_fixed, new_folder);
	}

	// Replace and clean old root
	Hpp::ByteV old_root = root_ref;
	replaceRootNode(root_now);
	ssize_t metadata_loc = getNodeMetadataLocation(old_root);
	HppAssert(metadata_loc >= 0, "Old root node not found!");
	Nodes::Metadata metadata = getNodeMetadata(metadata_loc);
	if (metadata.refs == 0) {
		clearOrphanNodeRecursively(metadata, metadata_loc, Nodes::TYPE_FOLDER);
	}

	setOrphanNodesFlag(orphan_nodes_flag_before);
}

void Archive::get(Paths const& sources, Hpp::Path const& dest)
{

	// Check to which directory sources should be put
	Hpp::Path realdest = dest;
	std::string customname = "";
	if (!dest.exists() || !dest.isDir()) {
		if (sources.size() != 1) {
			throw Hpp::Exception("Unable to extract multiple files/dirs under only one name! Did you forgot to create folder \"" + dest.toString() + "\"?");
		}
		realdest = dest.getParent();
		customname = dest.getFilename();
	}

	for (Paths::const_iterator sources_it = sources.begin();
	     sources_it != sources.end();
	     ++ sources_it) {

		Hpp::Path const& source = *sources_it;

		// First find source node
		Hpp::ByteV node_hash = root_ref;
		Nodes::FsMetadata node_fsmetadata;
		for (size_t part_id = 0; part_id < source.partsSize(); ++ part_id) {
			std::string const& part = source[part_id];

			// Read and construct parent folder
			Hpp::ByteV parent_srz = getNodeData(node_hash);
			Nodes::Folder parent(parent_srz);

			if (!parent.hasChild(part)) {
				throw Hpp::Exception("This archive does not contain path \"" + source.toString() + "\"!");
			}

			node_hash = parent.getChildHash(part);
			node_fsmetadata = parent.getChildFsMetadata(part);
		}

		// Do extracting recursively
		if (customname.empty()) {
			extractRecursively(node_hash, node_fsmetadata, realdest / source.getFilename());
		} else {
			extractRecursively(node_hash, node_fsmetadata, realdest / customname);
		}

	}

}

void Archive::list(Hpp::Path path, std::ostream* strm)
{
	path.forceToAbsolute();
	Nodes::Folders fpath;
	bool fpath_is_from_parent = false;
	try {
		fpath = getFoldersToPath(root_ref, path);
	}
	catch (Hpp::Exception) {
		// If path does not exist, then check
		// if it points to single file
		if (path.hasParent()) {
			Hpp::Path parent = path.getParent();
			fpath = getFoldersToPath(root_ref, parent);
			fpath_is_from_parent = true;
		} else {
			throw;
		}
	}
	Nodes::Folder const& folder = fpath.back();
	if (fpath_is_from_parent) {
		if (folder.hasChild(path.getFilename())) {
			(*strm) << path.toString() << std::endl;
		}
		return;
	}
	for (std::string child = folder.getFirstChild();
	     !child.empty();
	     child = folder.getNextChild(child)) {
		(*strm) << child << std::endl;
	}
}

void Archive::remove(Paths const& paths)
{
	// Ensure all paths exist!
	for (Paths::const_iterator paths_it = paths.begin();
	     paths_it != paths.end();
	     ++ paths_it) {
		Hpp::Path path = *paths_it;
		path.forceToAbsolute();
		if (!pathExists(path)) {
			throw Hpp::Exception("Unable to remove path \"" + path.toString() + "\" because it does not exist!");
		}
	}

	// The following operations will create new Nodes,
	// that will be orphans at first. Because of this,
	// the appropriate flag needs to be toggled on.
	bool orphan_nodes_flag_before = getOrphanNodesFlag();
	setOrphanNodesFlag(true);

	Hpp::ByteV root_now = root_ref;

	std::vector< Hpp::ByteV > nodes_to_remove;

	// Do removing and replace root node
	for (Paths::const_iterator paths_it = paths.begin();
	     paths_it != paths.end();
	     ++ paths_it) {
		Hpp::Path const& path = *paths_it;

		nodes_to_remove.push_back(root_now);

		root_now = doRemoving(root_now, path);
	}
	replaceRootNode(root_now);

	// Clean old root node and all extra nodes
	// that were created during removings.
	for (std::vector< Hpp::ByteV >::const_iterator nodes_to_remove_it = nodes_to_remove.begin();
	     nodes_to_remove_it != nodes_to_remove.end();
	     ++ nodes_to_remove_it) {
		Hpp::ByteV const& node_to_remove = *nodes_to_remove_it;

		ssize_t metadata_loc = getNodeMetadataLocation(node_to_remove);
		if (metadata_loc >= 0) {
			Nodes::Metadata metadata = getNodeMetadata(metadata_loc);
			if (metadata.refs == 0) {
				clearOrphanNodeRecursively(metadata, metadata_loc, Nodes::TYPE_FOLDER);
			}
		}

	}

	setOrphanNodesFlag(orphan_nodes_flag_before);

	// Write to disk
	io.flush();
}

void Archive::createNewFolders(Paths paths, Nodes::FsMetadata const& fsmetadata)
{
	// Ensure all paths are valid, i.e. their parents
	// exist and they themself does not exist yet.
	// Also convert all of them to absolute format.
	for (Paths::iterator paths_it = paths.begin();
	     paths_it != paths.end();
	     ++ paths_it) {
		Hpp::Path& path = *paths_it;
		path.forceToAbsolute();
		if (!path.hasParent()) {
			throw Hpp::Exception("Unable to create root directory!");
		}
		Hpp::Path parent = path.getParent();
		if (!pathExists(parent)) {
			throw Hpp::Exception("Unable to create directory \"" + path.toString() + "\", because its parent does not exist!");
		}
		if (pathExists(path)) {
// TODO: Ask if existing child should be overwritten!
			throw Hpp::Exception("Unable to create directory, because \"" + path.toString() + "\" already exists!");
		}
	}

// TODO: Ensure no path is given twice

	// The following operations will create new Nodes,
	// that will be orphans at first. Because of this,
	// the appropriate flag needs to be toggled on.
	bool orphan_nodes_flag_before = getOrphanNodesFlag();
	setOrphanNodesFlag(true);

	Hpp::ByteV root_now = root_ref;

	std::vector< Hpp::ByteV > nodes_to_remove;

	// Make new folders
	for (Paths::const_iterator paths_it = paths.begin();
	     paths_it != paths.end();
	     ++ paths_it) {
		Hpp::Path const& path = *paths_it;

		nodes_to_remove.push_back(root_now);

		root_now = doMakingOfNewFolder(root_now, path, fsmetadata);
	}
	replaceRootNode(root_now);

	// Clean old root node and all extra nodes
	// that were created during removings.
	for (std::vector< Hpp::ByteV >::const_iterator nodes_to_remove_it = nodes_to_remove.begin();
	     nodes_to_remove_it != nodes_to_remove.end();
	     ++ nodes_to_remove_it) {
		Hpp::ByteV const& node_to_remove = *nodes_to_remove_it;

		ssize_t metadata_loc = getNodeMetadataLocation(node_to_remove);
		if (metadata_loc >= 0) {
			Nodes::Metadata metadata = getNodeMetadata(metadata_loc);
			if (metadata.refs == 0) {
				clearOrphanNodeRecursively(metadata, metadata_loc, Nodes::TYPE_FOLDER);
			}
		}

	}

	setOrphanNodesFlag(orphan_nodes_flag_before);

	// Write to disk
	io.flush();
}

void Archive::finishPossibleInterruptedJournal(void)
{
	if (io.finishPossibleInterruptedJournal()) {

		// Because state of file has changed, it needs to be loaded again.
		loadStateFromFile("");

		HppAssert(verifyDataentriesAreValid(), "Data is failed after applying of interrupted journal!");

	}
}

void Archive::optimizeMetadata(void)
{
	#ifdef ENABLE_PROFILER
	Hpp::Profiler prof("Archive::optimizeMetadata");
	#endif

	Nodes::Metadata empty_metadata;
	empty_metadata.empty = true;

	// Options
// TODO: Later, change these options to dynamic, so they scale how much there is power in the machine.
	size_t METADATAS_TO_SORT_PER_ITER = 500;

	// If there are unsorted metadata entries, then sort them
	size_t metadatas_to_sort = getAmountOfNonemptyMetadataslotsAtRange(metas_s_size, metas_s_size + metas_us_size);
	if (metadatas_to_sort > 0) {
		// First minimize sorted section, so we get as much
		// extra space to unsorted section as possible.
		while (metas_s_size > 0 && getNodeMetadata(metas_s_size - 1).empty) {
			-- metas_s_size;
			++ metas_us_size;
		}
		io.doJournalAndWrites(writesRootRefAndCounts());
		HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");

		// Then, if needed, allocate more space for unsorted metadata
		ssize_t metas_us_size_target = metadatas_to_sort * 2;
		ssize_t alloc_change = metas_us_size_target - metas_us_size;
		if (alloc_change > 0) {
			allocateUnsortedMetadatas(alloc_change);
		}

		// Now fix unsorted section so that there is big
		// chunk of empty slots at the end of it. All
		// unsorted metadatas need to fit there later.
		size_t cleaner = metas_s_size + metas_us_size - 1;
		size_t next_cleaner_dump_pos = metas_s_size + metas_us_size - metadatas_to_sort - 1;
		while (cleaner >= metas_s_size + metas_us_size - metadatas_to_sort) {
			Nodes::Metadata metadata = getNodeMetadata(cleaner);
			// If this slot is not empty, then
			// move the metadata at here away
			if (!metadata.empty) {
				// Find place to dump this old metadata
				while (!getNodeMetadata(next_cleaner_dump_pos).empty) {
					HppAssert(next_cleaner_dump_pos > metas_s_size, "There are no place to dump old metadata!");
					-- next_cleaner_dump_pos;
				}
				// Do move
				Writes writes;
				writes += writesMetadata(empty_metadata, cleaner);
				writes += writesMetadata(metadata, next_cleaner_dump_pos);
				io.doJournalAndWrites(writes);
				HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");
				-- next_cleaner_dump_pos;
			}
			// This slot is cleaned, move to previous one
			-- cleaner;
		}

		// Now there is nice space to sort metadatas to. Sort
		// them using multiple iterations. This way, we can
		// be somewhat fast, but still save memory.
		for (size_t sorting = 0; sorting < metadatas_to_sort; sorting += METADATAS_TO_SORT_PER_ITER) {
			std::map< Nodes::Metadata, size_t > sortchunk;
// TODO: Optimize this loop, so that it will at every loop mark how many empties there was at the beginning!
			for (size_t slot = metas_s_size;
			     slot < metas_s_size + metas_us_size - metadatas_to_sort;
			     ++ slot) {
				Nodes::Metadata metadata = getNodeMetadata(slot);
				// Skip empty slots
				if (metadata.empty) {
					continue;
				}
				// If this metadata fills to
				// sortchunk, then add it there
				if (sortchunk.size() < METADATAS_TO_SORT_PER_ITER) {
					HppAssert(sortchunk.find(metadata) == sortchunk.end(), "Hash is already there!");
					sortchunk[metadata] = slot;
				} else if (metadata < sortchunk.rbegin()->first) {
					sortchunk[metadata] = slot;
					sortchunk.erase(sortchunk.rbegin()->first);
				}
			}
			// The metadatas at sortchunk are the first ones in
			// the order of remaining unsorted metadatas. Add them
			// to the end of unsorted section, as sorted ones.
			Writes writes;
			size_t target_pos = metas_s_size + metas_us_size - metadatas_to_sort + sorting;
			for (std::map< Nodes::Metadata, size_t >::const_iterator sortchunk_it = sortchunk.begin();
			     sortchunk_it != sortchunk.end();
			     ++ sortchunk_it) {
				size_t metadata_ofs = sortchunk_it->second;
				writes += writesMetadata(empty_metadata, metadata_ofs);
				writes += writesMetadata(sortchunk_it->first, target_pos);

				++ target_pos;
			}
			io.doJournalAndWrites(writes);
			HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");
		}

		// Minimize unsorted section and increase size of sorted one
		size_t metas_s_oldsize = metas_s_size;
		metas_s_size += metas_us_size - metadatas_to_sort;
		metas_us_size = metadatas_to_sort;
		io.doJournalAndWrites(writesRootRefAndCounts());
		HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");

		// Now move combine all metadatas to sorted section
		ssize_t s_read = (ssize_t)metas_s_oldsize - 1;
		size_t us_read = metas_s_size + metas_us_size - 1;
		size_t write = metas_s_size - 1;
		Nodes::Metadata s_meta;
		if (s_read >= 0) {
			s_meta = getNodeMetadata(s_read);
		} else {
			s_meta = empty_metadata;
		}
		Nodes::Metadata us_meta = getNodeMetadata(us_read);
		while (us_read >= metas_s_size) {
			// Ensure we have last metadata from both sections. Or
			// empty from sorted ones, if there is no more metadatas
			while (s_meta.empty && s_read > 0) {
				-- s_read;
				s_meta = getNodeMetadata(s_read);
			}
			HppAssert(!us_meta.empty, "Unexpected empty metadata at unsorted section!");

			Writes writes;
			if (s_meta.empty || s_meta < us_meta) {
				writes += writesMetadata(empty_metadata, us_read);
				writes += writesMetadata(us_meta, write);
				-- us_read;
				-- write;
				us_meta = getNodeMetadata(us_read);
			} else {
				HppAssert(us_meta < s_meta, "Same hash exists in both sections!");
				writes += writesMetadata(empty_metadata, s_read);
				writes += writesMetadata(s_meta, write);
				-- s_read;
				-- write;
				s_meta = getNodeMetadata(s_read);
			}
			io.doJournalAndWrites(writes);
			HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");
		}

	}

	// Remove empty gaps from sorted metadatas and shrink the section
	size_t write = 0;
	size_t read = 0;
	while (read < metas_s_size) {
		Nodes::Metadata metadata = getNodeMetadata(read);
		if (metadata.empty) {
			++ read;
			continue;
		}
		if (write == read) {
			++ read;
			++ write;
			continue;
		}
		Writes writes;
		writes += writesMetadata(empty_metadata, read);
		writes += writesMetadata(metadata, write);
		io.doJournalAndWrites(writes);
		HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");
		++ read;
		++ write;
	}
	metas_us_size += (metas_s_size - write);
	metas_s_size = write;
	io.doJournalAndWrites(writesRootRefAndCounts());
	HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");

	// Shrink empty unsorted section to zero
	if (metas_us_size > 0) {
		Writes writes;
		size_t metas_us_oldsize = metas_us_size;
		metas_us_size = 0;
		writes += writesEmpty(getSectionBegin(SECTION_DATA), metas_us_oldsize * Nodes::Metadata::ENTRY_SIZE - Nodes::Dataentry::HEADER_SIZE, true);
		writes += writesRootRefAndCounts();
		io.doJournalAndWrites(writes);
		HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");
	}

	HppAssert(verifyNoDoubleMetadatas(), "Same metadata is found twice!");
}

Nodes::Metadata Archive::getSortedMetadata(size_t metadata_ofs)
{
	if (metadata_ofs >= metas_s_size) {
		throw Hpp::Exception("Metadata offset overflow!");
	}
	return getNodeMetadata(metadata_ofs);
}

Nodes::Metadata Archive::getUnsortedMetadata(size_t metadata_ofs)
{
	if (metadata_ofs >= metas_us_size) {
		throw Hpp::Exception("Metadata offset overflow!");
	}
	return getNodeMetadata(metas_s_size + metadata_ofs);
}

uint64_t Archive::getNextDataentry(uint64_t data_entry_loc)
{
	Nodes::Dataentry de = getDataentry(data_entry_loc, false);
	return data_entry_loc + Nodes::Dataentry::HEADER_SIZE + de.size;
}

Nodes::Dataentry Archive::getDataentry(uint64_t loc, bool read_data, bool extract_data)
{
	if (loc + Nodes::Dataentry::HEADER_SIZE > datasec_end) {
		throw Hpp::Exception("Trying to read data entry that is beyond data section!");
	}
	if (loc < getSectionBegin(SECTION_DATA)) {
		throw Hpp::Exception("Data section underflow!");
	}
	Hpp::ByteV de_header = io.readPart(loc, Nodes::Dataentry::HEADER_SIZE);
	Nodes::Dataentry result(de_header);
	if (loc + Nodes::Dataentry::HEADER_SIZE + result.size > datasec_end) {
		throw Hpp::Exception("Invalid data entry! Its size seems to overflow beyond data section!");
	}
	if (read_data && !result.empty) {
		result.data = io.readPart(loc + Nodes::Dataentry::HEADER_SIZE, result.size);
		if (extract_data) {
			// Read and extract data
			Hpp::Decompressor decompressor;
			decompressor.init();
			try {
				decompressor.decompress(result.data);
				result.data = decompressor.read();
				result.data += decompressor.deinit();
			}
			catch (Hpp::Exception const& e) {
				throw Hpp::Exception(std::string("Unable to extract compressed data of node! Reason: ") + e.what());
			}
		}
	}
	return result;
}

uint64_t Archive::getJournalLocation(void)
{
	Hpp::ByteV journal_loc_srz = io.readPart(getSectionBegin(SECTION_JOURNAL_INFO), 8);
	return Hpp::cStrToUInt64(&journal_loc_srz[0]);
}

Hpp::ByteV Archive::getNodeData(Hpp::ByteV const& node_hash)
{
	HppAssert(node_hash.size() == NODE_HASH_SIZE, "Invalid hash size!");
	// Get metadata
	ssize_t metadata_loc = getNodeMetadataLocation(node_hash);
	if (metadata_loc < 0) {
		throw Hpp::Exception("Node " + Hpp::byteVToHexV(node_hash) + " not found!");
	}

	return getNodeData(metadata_loc);
}

inline bool Archive::pathExists(Hpp::Path const& path)
{
	HppAssert(path.isAbsolute(), "Path must be absolute!");

	Hpp::ByteV node_hash = root_ref;
	for (size_t part_id = 0; part_id < path.partsSize(); ++ part_id) {
		std::string part = path[part_id];

		Nodes::Folder folder(getNodeData(node_hash));

		if (!folder.hasChild(part)) {
			return false;
		}

		node_hash = folder.getChildHash(part);

	}

	return true;
}

bool Archive::verifyDataentriesAreValid(bool throw_exception)
{
	size_t nodes_size1 = getAmountOfNonemptyMetadataslotsAtRange(0, metas_s_size + metas_us_size);

	size_t check_loc = getSectionBegin(SECTION_DATA);
	size_t nodes_size2 = 0;
	while (check_loc < datasec_end) {

		Nodes::Dataentry check_de;
		try {
			check_de = getDataentry(check_loc, false);
		}
		catch (Hpp::Exception const& e)
		{
			if (throw_exception) {
				throw Hpp::Exception("Unable to load dataentry! Reason: " + std::string(e.what()));
			}
			return false;
		}

		if (!check_de.empty) {
			++ nodes_size2;
		}

		check_loc += Nodes::Dataentry::HEADER_SIZE + check_de.size;
	}

	if (nodes_size1 != nodes_size2) {
		if (throw_exception) {
			throw Hpp::Exception("Number of nodes in metadatas(" + Hpp::sizeToStr(nodes_size1) + ") and in dataentries(" + Hpp::sizeToStr(nodes_size2) + ") do not match!");
		}
		return false;
	}

	return true;
}

bool Archive::verifyNoDoubleMetadatas(bool throw_exception)
{
	std::set< Hpp::ByteV > hashes;
	for (size_t metadata_id = 0;
	     metadata_id < metas_s_size + metas_us_size;
	     ++ metadata_id) {
		Nodes::Metadata metadata = getNodeMetadata(metadata_id);
		if (!metadata.empty) {
			Hpp::ByteV const& hash = metadata.hash;
			if (!hashes.insert(hash).second) {
				if (throw_exception) {
					throw Hpp::Exception("Hash " + Hpp::byteVToHexV(hash) + " exists multiple times on metadatas!");
				}
				return false;
			}
		}
	}

	return true;
}

bool Archive::verifyReferences(bool throw_exception)
{
	size_t const MAX_CHECK_AMOUNT_PER_ITERATION = 5000;

	size_t metadata_ofs = 0;
	while (metadata_ofs < metas_s_size + metas_us_size) {

		// Pick some Nodes for reference count check
		std::map< Hpp::ByteV, uint32_t > refs;
		while (refs.size() < MAX_CHECK_AMOUNT_PER_ITERATION && metadata_ofs < metas_s_size + metas_us_size) {
			Nodes::Metadata metadata = getNodeMetadata(metadata_ofs);
			++ metadata_ofs;
			if (!metadata.empty) {
				refs[metadata.hash] = metadata.refs;
			}
		}

		// Go all nodes through, and calculate how many
		// references there are to the selected ones
		std::map< Hpp::ByteV, uint32_t > refs_check;
		// If there is root node, then add one reference to it
		if (refs.find(root_ref) != refs.end()) {
			refs_check[root_ref] = 1;
		}
		size_t check_loc = getSectionBegin(SECTION_DATA);
		while (check_loc < datasec_end) {

			Nodes::Dataentry check_de = getDataentry(check_loc, true, true);

			if (!check_de.empty) {

				// Get children of this Node
				Nodes::Node* node = spawnNodeFromDataentry(check_de);
				Nodes::Children children = node->getChildrenNodes();
				delete node;

				for (Nodes::Children::const_iterator children_it = children.begin();
				     children_it != children.end();
				     ++ children_it) {
					Nodes::Child const& child = *children_it;
					if (refs.find(child.hash) != refs.end()) {
						std::map< Hpp::ByteV, uint32_t >::iterator refs_check_find = refs_check.find(child.hash);
						if (refs_check_find != refs_check.end()) {
							++ refs_check_find->second;
						} else {
							refs_check[child.hash] = 1;
						}
					}
				}

			}

			check_loc += Nodes::Dataentry::HEADER_SIZE + check_de.size;
		}

		// Now ensure all reference counts are same.
		for (std::map< Hpp::ByteV, uint32_t >::const_iterator refs_it = refs.begin();
		     refs_it != refs.end();
		     ++ refs_it) {
			Hpp::ByteV hash = refs_it->first;
			uint32_t r = refs_it->second;
			std::map< Hpp::ByteV, uint32_t >::const_iterator refs_check_find = refs_check.find(hash);
			uint32_t r_check = 0;
			if (refs_check_find != refs_check.end()) {
				r_check = refs_check_find->second;
			}
			if (r != r_check) {
				if (throw_exception) {
					throw Hpp::Exception("Reference count for node " + Hpp::byteVToHexV(hash) + " is claimed to be " + Hpp::sizeToStr(r) + ", but when checked, only " + Hpp::sizeToStr(r_check) + " was found referencing to it!");
				}
				return false;
			}
		}

	}

	return true;
}

void Archive::closeAndOpenFile(Hpp::Path const& path)
{
	io.closeAndOpenFile(path);
}

void Archive::loadStateFromFile(std::string const& password)
{

	// Make sure the file contains valid data

	// Identifier
	size_t const IDENTIFIER_LEN = strlen(ARCHIVE_IDENTIFIER);
	try {
		Hpp::ByteV identifier = io.readPart(getSectionBegin(SECTION_IDENTIFIER), IDENTIFIER_LEN, true);
		if (strncmp((char*)&identifier[0], ARCHIVE_IDENTIFIER, IDENTIFIER_LEN) != 0) {
			throw 0xbeef;
		}
	}
	catch ( ... ) {
		throw Hpp::Exception("Not a valid archive file!");
	}

	// Version
	try {
		Hpp::ByteV version_bytev = io.readPart(getSectionBegin(SECTION_VERSION), 1, true);
		if (version_bytev[0] != 0) {
			throw 0xbeef;
		}
	}
	catch ( ... ) {
		throw Hpp::Exception("Version of archive is not supported!");
	}

	// Do this only if crypto key is not set yet
	if (crypto_key.empty()) {

		// Crypto flag and possible salt
		Hpp::ByteV salt;
		try {
			Hpp::ByteV crypto_enabled_bytev = io.readPart(getSectionBegin(SECTION_CRYPTO_FLAG), 1, true);
			if (crypto_enabled_bytev[0]) {
				salt = io.readPart(getSectionBegin(SECTION_SALT), SALT_SIZE, true);
			}
		}
		catch ( ... ) {
			throw Hpp::Exception("Archive is corrupted!");
		}

		// Ensure password is set properly
		if (!password.empty() && salt.empty()) {
			throw Hpp::Exception("Archive does not need password!");
		}
		if (password.empty() && !salt.empty()) {
			throw Hpp::Exception("Archive is password protected!");
		}

		// If password is used, then initialize it and ensure it is correct
		if (!password.empty()) {
			crypto_key = generateCryptoKey(password, salt);

			// Inform FileIO about this
			io.enableCrypto(crypto_key);

			crypto_password_verifier = io.readPart(getSectionBegin(SECTION_PASSWORD_VERIFIER), PASSWORD_VERIFIER_SIZE);
			Hpp::ByteV::iterator pw_verif_half = crypto_password_verifier.begin() + PASSWORD_VERIFIER_SIZE / 2;

			if (!std::equal(crypto_password_verifier.begin(), pw_verif_half, pw_verif_half)) {
				throw Hpp::Exception("Invalid password!");
			}
			crypto_password_verifier.erase(pw_verif_half, crypto_password_verifier.end());
		}

	}

	// Read reference to root node, allocations
	// of metadata, and ending of data section.
	Hpp::ByteV root_refs_and_sizes = io.readPart(getSectionBegin(SECTION_ROOT_REF_AND_SIZES), NODE_HASH_SIZE + 3*8);
	root_ref = Hpp::ByteV(root_refs_and_sizes.begin(), root_refs_and_sizes.begin() + NODE_HASH_SIZE);
	metas_s_size = Hpp::cStrToUInt64(&root_refs_and_sizes[NODE_HASH_SIZE]);
	metas_us_size = Hpp::cStrToUInt64(&root_refs_and_sizes[NODE_HASH_SIZE + 8]);
	datasec_end = Hpp::cStrToUInt64(&root_refs_and_sizes[NODE_HASH_SIZE + 16]);

	// Inform FileIO about new data end
	io.setEndOfData(datasec_end);

	// Check if journal or orphan nodes exists
	io.readJournalflagState();
	orphan_nodes_exists = (io.readPart(getSectionBegin(SECTION_ORPHAN_NODES_FLAG), 1)[0] >= 128);

}

ssize_t Archive::getNodeMetadataLocation(Hpp::ByteV const& hash)
{
	#ifdef ENABLE_PROFILER
	Hpp::Profiler prof("Archive::getNodeMetadataLocation");
	#endif

	HppAssert(hash.size() == NODE_HASH_SIZE, "Invalid hash size!");

	// First check sorted section
	if (metas_s_size > 0) {
		size_t begin = getSectionBegin(SECTION_METADATA_SORTED);
		size_t search_begin = 0;
		size_t search_end = metas_s_size - 1;
		while (search_begin <= search_end) {
			// If there are only two or less slots
			// left, then check both of them
			if (search_end - search_begin <= 1) {
				for (size_t search2 = search_begin; search2 <= search_end; ++ search2) {
					Hpp::ByteV metadata_srz = io.readPart(begin + search2 * Nodes::Metadata::ENTRY_SIZE, Nodes::Metadata::ENTRY_SIZE);
					// In case of empty, skip this
					if (metadata_srz[0] >= 128) {
						continue;
					}
					// Check if this is the correct hash
					if (std::equal(hash.begin(), hash.end(), metadata_srz.begin() + 1)) {
						return search2;
					}
				}
				// If nothing was found, then give up
				break;
			}

			// Halve search. Because of possible empty
			// slots between, make two pointers for half
			// point, and search first and last non-empty.
			ssize_t small_half = (search_begin + search_end) / 2;
			ssize_t big_half = small_half;

			while (small_half >= ssize_t(search_begin)) {
				// If current slot is not empty,
				// then break from this loop.
				Hpp::ByteV metadata_srz = io.readPart(begin + small_half * Nodes::Metadata::ENTRY_SIZE, Nodes::Metadata::ENTRY_SIZE);
				if (metadata_srz[0] < 128) {
					break;
				}
				-- small_half;
			}
			if (small_half < big_half) {
				++ big_half;
				while (big_half <= ssize_t(search_end)) {
					// If current slot is not empty,
					// then break from this loop.
					Hpp::ByteV metadata_srz = io.readPart(begin + big_half * Nodes::Metadata::ENTRY_SIZE, Nodes::Metadata::ENTRY_SIZE);
					if (metadata_srz[0] < 128) {
						break;
					}
					++ big_half;
				}
			}

			// If there was item in the half slot, then check only it
			if (small_half == big_half) {
				Hpp::ByteV metadata_srz = io.readPart(begin + small_half * Nodes::Metadata::ENTRY_SIZE, Nodes::Metadata::ENTRY_SIZE);
				int compare = Hpp::compare(hash.begin(), hash.end(), metadata_srz.begin() + 1);
				// Check if this is the correct hash
				if (compare == 0) {
					return small_half;
				}
				// Check if the searched hash is greater than the one at center
				if (compare > 0) {
					search_begin = small_half + 1;
					continue;
				} else {
					search_end = small_half - 1;
					continue;
				}
			}
			// There was no item in half slot. First compare to
			// smaller hash, if there is metadata entry there.
			if (small_half >= ssize_t(search_begin)) {
				Hpp::ByteV metadata_srz = io.readPart(begin + small_half * Nodes::Metadata::ENTRY_SIZE, Nodes::Metadata::ENTRY_SIZE);
				if (metadata_srz[0] >= 128) {
					throw Hpp::Exception("Unexpected empty metadata slot!");
				}
				int small_compare = Hpp::compare(hash.begin(), hash.end(), metadata_srz.begin() + 1);
				// Check if this is the correct hash
				if (small_compare == 0) {
					return small_half;
				}
				// If the searched hash is smaller than this
				// one here, then we know that the correct
				// one might be found before this one.
				if (small_compare < 0) {
					search_end = small_half - 1;
					continue;
				}
			}

			// Then compare to bigger hash, if
			// there is metadata entry there.
			if (big_half <= ssize_t(search_end)) {
				Hpp::ByteV metadata_srz = io.readPart(begin + big_half * Nodes::Metadata::ENTRY_SIZE, Nodes::Metadata::ENTRY_SIZE);
				if (metadata_srz[0] >= 128) {
					throw Hpp::Exception("Unexpected empty metadata slot!");
				}
				int big_compare = Hpp::compare(hash.begin(), hash.end(), metadata_srz.begin() + 1);
				// Check if this is the correct hash
				if (big_compare == 0) {
					return big_half;
				}
				// If correct hash is smaller than this
				// half, then it means it is not found.
				if (big_compare < 0) {
					break;
				}
				// Searched hash is bigger, so that means
				// it will be found after this half
				search_begin = big_half + 1;
				continue;
			}

			// The hash cannot be found from here
			break;

		}
	}
	#ifndef NDEBUG
	{
		size_t begin = getSectionBegin(SECTION_METADATA_SORTED);
		for (size_t search = 0; search < metas_s_size; ++ search) {
			Hpp::ByteV metadata_srz = io.readPart(begin + search * Nodes::Metadata::ENTRY_SIZE, Nodes::Metadata::ENTRY_SIZE);
			// In case of empty, skip this
			if (metadata_srz[0] >= 128) {
				continue;
			}
			// Check if this is the correct hash
			if (std::equal(hash.begin(), hash.end(), metadata_srz.begin() + 1)) {
				throw Hpp::Exception("Hash " + Hpp::byteVToHexV(Hpp::ByteV(metadata_srz.begin() + 1, metadata_srz.begin() + 1 + NODE_HASH_SIZE)) + " could not be found from the section of sorted metadatas, but it exists there!");
			}
		}
	}
	#endif

	// Then check unsorten section
	size_t begin = getSectionBegin(SECTION_METADATA_UNSORTED);
	for (size_t search = 0; search < metas_us_size; ++ search) {
		Hpp::ByteV metadata_srz = io.readPart(begin + search * Nodes::Metadata::ENTRY_SIZE, Nodes::Metadata::ENTRY_SIZE);
		// In case of empty, skip this
		if (metadata_srz[0] >= 128) {
			continue;
		}
		// Check if this is the correct hash
		if (std::equal(hash.begin(), hash.end(), metadata_srz.begin() + 1)) {
			return metas_s_size + search;
		}
	}

	// Node was not found
	return -1;
}

Nodes::Metadata Archive::getNodeMetadata(Hpp::ByteV const& node_hash, ssize_t* loc)
{
	HppAssert(node_hash.size() == NODE_HASH_SIZE, "Invalid hash size!");
	ssize_t metadata_loc = getNodeMetadataLocation(node_hash);
	if (loc) *loc = metadata_loc;
	if (metadata_loc < 0) {
		throw Hpp::Exception("Node " + Hpp::byteVToHexV(node_hash) + " not found!");
	}
	return getNodeMetadata(metadata_loc);
}

Nodes::Metadata Archive::getNodeMetadata(uint64_t metadata_loc)
{
	size_t metadata_loc_abs = getSectionBegin(SECTION_METADATA_SORTED) + metadata_loc * Nodes::Metadata::ENTRY_SIZE;

	Hpp::ByteV metadata_srz = io.readPart(metadata_loc_abs, Nodes::Metadata::ENTRY_SIZE);
	Nodes::Metadata metadata = Nodes::Metadata(metadata_srz);

	return metadata;
}

Hpp::ByteV Archive::getNodeData(uint64_t metadata_loc)
{
	// Get metadata
	Nodes::Metadata metadata = getNodeMetadata(metadata_loc);

	return getNodeData(metadata);
}

Hpp::ByteV Archive::getNodeData(Nodes::Metadata const& metadata)
{

	// Read dataentry header
	Nodes::Dataentry de = getDataentry(metadata.data_loc, true, true);
	return de.data;
}

ssize_t Archive::calculateAmountOfEmptySpace(uint64_t loc)
{
	size_t empty_space = 0;
	while (true) {

		if (loc == datasec_end) {
			return -1;
		}

		Nodes::Dataentry de = getDataentry(loc, false);

		if (!de.empty) {
			break;
		}
// TODO: It would be good to check here, that data entries do not overflow!

		empty_space += Nodes::Dataentry::HEADER_SIZE + de.size;
		loc += Nodes::Dataentry::HEADER_SIZE + de.size;
	}
	return empty_space;
}

Nodes::Folders Archive::getFoldersToPath(Hpp::ByteV const& root, Hpp::Path const& path)
{
	HppAssert(path.isAbsolute(), "Path must be absolute!");

	Nodes::Folders result;
	result.reserve(path.partsSize() + 1);

	Nodes::Folder root_folder(getNodeData(root));
	result.push_back(root_folder);

	Nodes::Folder parent_folder = root_folder;
	for (size_t subfolder_depth = 0; subfolder_depth < path.partsSize(); ++ subfolder_depth) {
		std::string subfolder_name = path[subfolder_depth];

		if (!parent_folder.hasChild(subfolder_name) ||
		    parent_folder.getChildType(subfolder_name) != Nodes::FSTYPE_FOLDER) {
			throw Hpp::Exception("Path does not exist!");
		}

		Nodes::Folder subfolder(getNodeData(parent_folder.getChildHash(subfolder_name)));

		result.push_back(subfolder);
		parent_folder = subfolder;
	}

	return result;
}

size_t Archive::getEmptyMetadataSlot(void)
{

	size_t metas_us_begin = getSectionBegin(SECTION_METADATA_UNSORTED);
	for (size_t metas_us_id = 0;
	     metas_us_id < metas_us_size;
	     ++ metas_us_id) {
		if (Nodes::Metadata(io.readPart(metas_us_begin + metas_us_id * Nodes::Metadata::ENTRY_SIZE, Nodes::Metadata::ENTRY_SIZE)).empty) {
			return metas_us_id;
		}
	}

	// Make more space to unsorted metadatas
	size_t old_metas_size = metas_us_size;

	allocateUnsortedMetadatas(std::max< uint64_t >(1, metas_us_size));

	return old_metas_size;
}

size_t Archive::getAmountOfNonemptyMetadataslotsAtRange(size_t begin, size_t end)
{
	size_t result = 0;
	for (size_t slot = begin; slot < end; ++ slot) {
		if (!getNodeMetadata(slot).empty) {
			++ result;
		}
	}
	return result;
}

Hpp::ByteV Archive::doRemoving(Hpp::ByteV const& root, Hpp::Path const& path)
{
// TODO: Output something!

	// Force path to absolute form
	Hpp::Path path_abs = path;
	path_abs.forceToAbsolute();

	// File/Folder is removed from its parent, so find that first
	if (!path_abs.hasParent()) {
		throw Hpp::Exception("Unable to remove root!");
	}
	Hpp::Path parent = path_abs.getParent();
	std::string child_name = path_abs.getFilename();

	Nodes::Folders fpath;
	try {
		fpath = getFoldersToPath(root, parent);
	}
	catch (Hpp::Exception) {
		return root;
	}

	// Replace last folder with cloned one, that has the child removed
	HppAssert(!fpath.empty(), "Folder path must not be empty!");

	Nodes::Folder folder = fpath.back();
	if (!folder.hasChild(child_name)) {
		return root;
	}
	folder.removeChild(child_name);

	Hpp::ByteV new_root = replaceLastFolder(fpath, parent, folder);

	return new_root;
}

Hpp::ByteV Archive::doMakingOfNewFolder(Hpp::ByteV const& root,
                                        Hpp::Path const& path,
                                        Nodes::FsMetadata const& fsmetadata)
{
// TODO: Output something!

	HppAssert(path.hasParent(), "No parent!");
	Hpp::Path parent = path.getParent();
	std::string child_name = path.getFilename();

	Nodes::Folders fpath = getFoldersToPath(root, parent);

	// Replace last folder with cloned one, that has the child removed
	HppAssert(!fpath.empty(), "Folder path must not be empty!");

	Nodes::Folder folder = fpath.back();
	if (folder.hasChild(child_name)) {
		throw Hpp::Exception("Unable to create new folder because there is already something with the same name!");
	}
	Nodes::Folder child;
	spawnOrGetNode(&child);
	folder.setChild(child_name, Nodes::FSTYPE_FOLDER, child.getHash(), fsmetadata);

	Hpp::ByteV new_root = replaceLastFolder(fpath, parent, folder);

	return new_root;
}

Hpp::ByteV Archive::replaceLastFolder(Nodes::Folders const& fpath,
                                      Hpp::Path const& path,
                                      Nodes::Folder folder)
{
	HppAssert(!fpath.empty(), "No folders!");

	// Ensure this new folder exists
	spawnOrGetNode(&folder);

	// If there is only one folder (root) in path,
	// then return this folder immediately.
	if (fpath.size() == 1) {
		return folder.getHash();
	}

	// Get info about this new folder that will be used
	Hpp::ByteV new_folder = folder.getHash();
	HppAssert(fpath.size() - 2 < path.partsSize(), "Overflow!");
	std::string new_folder_name = path[fpath.size() - 2];
	Nodes::FsMetadata new_folder_fsmetadata = fpath[fpath.size() - 2].getChildFsMetadata(new_folder_name);

	// Go folder path through from deepest to the root.
	for (ssize_t folders_id = fpath.size() - 2;
	     folders_id >= 0;
	     -- folders_id) {
		Nodes::Folder folder = fpath[folders_id];

		// Replace one of children
		folder.setChild(new_folder_name, Nodes::FSTYPE_FOLDER, new_folder, new_folder_fsmetadata);

		// Add this folder to the archive
		spawnOrGetNode(&folder);

		// Hash of this new folder is always needed
		new_folder = folder.getHash();

		// Get specs of this Folder for its parent, if it exists
		if (folders_id > 0) {
			new_folder_name = path[folders_id - 1];
			new_folder_fsmetadata = fpath[folders_id - 1].getChildFsMetadata(new_folder_name);
		}
	}

	return new_folder;
}

void Archive::replaceRootNode(Hpp::ByteV const& new_root)
{
	if (new_root == root_ref) {
		return;
	}

	// Get and update metadata
	ssize_t metadata_old_loc;
	ssize_t metadata_new_loc;
	HppAssert(root_ref.size() == NODE_HASH_SIZE, "Invalid hash size!");
	HppAssert(new_root.size() == NODE_HASH_SIZE, "Invalid hash size!");
	Nodes::Metadata metadata_old = getNodeMetadata(root_ref, &metadata_old_loc);
	Nodes::Metadata metadata_new = getNodeMetadata(new_root, &metadata_new_loc);
	if (metadata_old.refs == 0) {
		throw Hpp::Exception("Unable to update root node, because old root node has zero refrences!");
	}
	-- metadata_old.refs;
	++ metadata_new.refs;

	// Update root node
	root_ref = new_root;

	// Prepare writes
	Writes writes;
	writes += writesRootRefAndCounts();
	writes += writesMetadata(metadata_old, metadata_old_loc);
	writes += writesMetadata(metadata_new, metadata_new_loc);

	// Write
	io.doJournalAndWrites(writes);
	HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");

}

Writes Archive::writesPasswordVerifier(void)
{
	if (crypto_key.empty()) {
		throw Hpp::Exception("Writing password verifier requires cryptokey set!");
	}

	Hpp::ByteV part;
	part.reserve(PASSWORD_VERIFIER_SIZE);
	part += crypto_password_verifier;
	part += crypto_password_verifier;

	Writes result;
	result[getSectionBegin(SECTION_PASSWORD_VERIFIER)] = part;
	return result;
}

Writes Archive::writesOrphanNodesFlag(bool orphans_exists)
{
	Hpp::ByteV flag_serialized;
	if (orphans_exists) {
		flag_serialized.push_back(Hpp::randomInt(128, 255));
	} else {
		flag_serialized.push_back(Hpp::randomInt(0, 127));
	}

	Writes result;
	result[getSectionBegin(SECTION_ORPHAN_NODES_FLAG)] = flag_serialized;
	return result;
}

Writes Archive::writesSetNodeRefs(Hpp::ByteV const& hash, uint32_t refs)
{
	HppAssert(hash.size() == NODE_HASH_SIZE, "Invalid hash size!");
	ssize_t metadata_loc = getNodeMetadataLocation(hash);
	if (metadata_loc < 0) {
		throw Hpp::Exception("Node " + Hpp::byteVToHexV(hash) + " not found!");
	}
	size_t metadata_loc_abs = getSectionBegin(SECTION_METADATA_SORTED) + metadata_loc * Nodes::Metadata::ENTRY_SIZE;
	Nodes::Metadata meta(io.readPart(metadata_loc_abs, Nodes::Metadata::ENTRY_SIZE));
	meta.refs = refs;
	return writesMetadata(meta, metadata_loc);
}

Writes Archive::writesMetadata(Nodes::Metadata const& meta, size_t metadata_loc)
{
	HppAssert(metadata_loc < metas_s_size + metas_us_size, "Metadata too big!");
	size_t begin = getSectionBegin(SECTION_METADATA_SORTED);
	Writes result;
	result[begin + metadata_loc * Nodes::Metadata::ENTRY_SIZE] = meta.serialize();

	HppAssert(result.begin()->first + result.begin()->second.size() <= getSectionBegin(SECTION_DATA), "Fail!");
	return result;
}

Writes Archive::writesRootRefAndCounts(void)
{
	HppAssert(root_ref.size() == NODE_HASH_SIZE, "Root reference has invalid size!");

	Hpp::ByteV part1;
	part1.reserve(ROOT_REF_AND_SIZES_SIZE);
	part1 += root_ref;
	part1 += Hpp::uInt64ToByteV(metas_s_size);
	part1 += Hpp::uInt64ToByteV(metas_us_size);
	part1 += Hpp::uInt64ToByteV(datasec_end);

	HppAssert(part1.size() + getSectionBegin(SECTION_ROOT_REF_AND_SIZES) == getSectionBegin(SECTION_METADATA_SORTED), "Fail!");
	Writes result;
	result[getSectionBegin(SECTION_ROOT_REF_AND_SIZES)] = part1;

	return result;
}

Writes Archive::writesData(uint64_t begin, Nodes::Type type, Hpp::ByteV const& data, uint32_t empty_space_after)
{
	HppAssert(begin + Nodes::Dataentry::HEADER_SIZE + data.size() + empty_space_after <= datasec_end, "Trying to write data after datasection!");

	Writes result;
	result[begin] = Hpp::uInt32ToByteV(data.size() & Nodes::Dataentry::MASK_DATA);
	result[begin][0] |= uint8_t(type) << 5;
	result[begin + Nodes::Dataentry::HEADER_SIZE] = data;

	if (empty_space_after > 0) {
		HppAssert(empty_space_after >= Nodes::Dataentry::HEADER_SIZE, "Empty after data must be zero, or at least four!");
		result[begin + Nodes::Dataentry::HEADER_SIZE + data.size()] = Hpp::uInt32ToByteV(((empty_space_after - Nodes::Dataentry::HEADER_SIZE) & Nodes::Dataentry::MASK_DATA) | Nodes::Dataentry::MASK_EMPTY);
	}
	return result;
}

Writes Archive::writesEmpty(uint64_t begin, uint32_t size, bool try_to_join_to_next_dataentry)
{
	HppAssert(begin + Nodes::Dataentry::HEADER_SIZE + size, "Trying to write empty after datasection!");

	if (try_to_join_to_next_dataentry) {
		// Check if entry after this one is empty too. If so, then merge them
		size_t check_loc = begin + Nodes::Dataentry::HEADER_SIZE + size;
		while (check_loc != datasec_end) {
			HppAssert(check_loc < datasec_end, "Empty data entry overflows data section!");
			Nodes::Dataentry de_check = getDataentry(check_loc, false);
			if (!de_check.empty) {
				break;
			}
			size += Nodes::Dataentry::HEADER_SIZE + de_check.size;
			check_loc += Nodes::Dataentry::HEADER_SIZE + de_check.size;
		}
	}

	Writes result;
	Hpp::ByteV header = Hpp::uInt32ToByteV((size & Nodes::Dataentry::MASK_DATA) | Nodes::Dataentry::MASK_EMPTY);
	result[begin] = header;

	return result;
}

Writes Archive::writesClearNode(Nodes::Metadata const& metadata, size_t metadata_loc)
{
	// Read length of compressed data
	Nodes::Dataentry de = getDataentry(metadata.data_loc, false);
	if (de.empty) {
		throw Hpp::Exception("Unexpected empty data entry!");
	}

	Writes result;
	// Clear data entry
	result += writesEmpty(metadata.data_loc, de.size, true);
	// Clear metadata
	Nodes::Metadata empty_metadata;
	empty_metadata.empty = true;
	result += writesMetadata(empty_metadata, metadata_loc);

	return result;
}

void Archive::allocateUnsortedMetadatas(size_t amount)
{
	Nodes::Metadata empty_metadata;
	empty_metadata.empty = true;

	// Data area should be moved to get space for new unsorted metadata
	size_t bytes_alloc = amount * Nodes::Metadata::ENTRY_SIZE;

	// Read how much there is empty data
	// at the beginning of data section
	size_t datasec_begin = getSectionBegin(SECTION_DATA);
	ssize_t empty_bytes_after_datasec_begin = calculateAmountOfEmptySpace(datasec_begin);

	// If there is only empty data, then mark
	// data section to have zero length
	if (empty_bytes_after_datasec_begin < 0) {

		metas_us_size += amount;
		datasec_end = getSectionBegin(SECTION_DATA);

		// Inform FileIO about new data end
		io.setEndOfData(datasec_end);

		Writes writes;
		writes += writesRootRefAndCounts();
		for (size_t reset = 0; reset < amount; ++ reset) {
			writes += writesMetadata(empty_metadata, metas_s_size + metas_us_size - amount + reset);
		}
		io.doJournalAndWrites(writes);
		HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");

	}
	// If there is not infinite amount of emptiness,
	// then we might need to do some data relocations.
	else {

		// Move data entries until there is enough empty data
		uint64_t min_dataentry_loc = datasec_begin + bytes_alloc;
		while (empty_bytes_after_datasec_begin != (ssize_t)bytes_alloc && empty_bytes_after_datasec_begin < (ssize_t)bytes_alloc + (ssize_t)Nodes::Dataentry::HEADER_SIZE) {
			// Read length of next data entry
			uint64_t moved_de_loc = datasec_begin + empty_bytes_after_datasec_begin;
			Nodes::Dataentry moved_de = getDataentry(moved_de_loc, false);
			if (moved_de.empty) {
				throw Hpp::Exception("Unexpected empty data entry!");
			}

			// Loop until space is found
			uint64_t de_to_check_loc = moved_de_loc;
			uint64_t de_to_check_end = de_to_check_loc + Nodes::Dataentry::HEADER_SIZE + moved_de.size;
			while (true) {

				// Check how much there is empty
				// space after this data entry.
				ssize_t empty_bytes_after_de = calculateAmountOfEmptySpace(de_to_check_end);

				// If there is infinite amount of empty data,
				// then relocate data entry here. But be sure
				// to move it far enough, so it wont get in the
				// way of new metadatas. Also, be sure that the
				// empty space between it and the last
				// dataentry and the future data begin is
				// either zero, or >= 8, so there can be empty
				// space between them.
				if (empty_bytes_after_de < 0) {
					uint64_t moved_new_loc;
					if (min_dataentry_loc > de_to_check_end) {
						moved_new_loc = min_dataentry_loc;
						size_t empty_after_last_de = moved_new_loc - de_to_check_end;
						if (empty_after_last_de != 0 && empty_after_last_de < 8) {
							moved_new_loc += 8;
						}
					} else {
						moved_new_loc = de_to_check_end;
					}
					// If last de was the one being moved,
					// then empty before dest needs to be
					// calculated from begin of data section.
					uint64_t empty_b4_dest;
					if (moved_de_loc == de_to_check_loc) empty_b4_dest = datasec_begin;
					else empty_b4_dest = de_to_check_end;
					moveData(moved_de_loc, moved_new_loc, datasec_begin, empty_b4_dest);
					HppAssert(verifyDataentriesAreValid(), "Dataentries are broken!");
					break;
				}

				// There was no infinite amount of empty space,
				// so check if movable data entry fits here and
				// is not in the way of new metadatas.
				size_t empty_data_end = de_to_check_end + empty_bytes_after_de;
				uint64_t possible_new_loc = std::max(min_dataentry_loc, de_to_check_end);
				uint64_t possible_new_loc_end = possible_new_loc + Nodes::Dataentry::HEADER_SIZE + moved_de.size;
				if (possible_new_loc_end == empty_data_end || possible_new_loc_end <= empty_data_end - Nodes::Dataentry::HEADER_SIZE) {
					// If last de was the one being moved,
					// then empty before dest needs to be
					// calculated from begin of data section.
					uint32_t empty_b4_dest;
					if (moved_de_loc == de_to_check_loc) empty_b4_dest = datasec_begin;
					else empty_b4_dest = de_to_check_end;
					moveData(moved_de_loc, possible_new_loc, datasec_begin, empty_b4_dest);
					break;
				}

				// The moved data entry did not fit to
				// empty space here, so search behind
				// next non-empty data entry.
				Nodes::Dataentry de_to_check = getDataentry(empty_data_end, false);
				if (de_to_check.empty) {
					throw Hpp::Exception("Unexpected empty data entry!");
				}
				de_to_check_loc = empty_data_end;
				de_to_check_end = de_to_check_loc + Nodes::Dataentry::HEADER_SIZE + de_to_check.size;

			}

			// Data entry from begin should be moved
			// now, so update amount of empty data.
			empty_bytes_after_datasec_begin = calculateAmountOfEmptySpace(datasec_begin);
			HppAssert(empty_bytes_after_datasec_begin >= 0, "Should not be infinite empty here!");

		}

		// Reduce bytes allocation from empty space,
		// so it tell how much there is really left.
		HppAssert(empty_bytes_after_datasec_begin >= (ssize_t)bytes_alloc, "Too small amount of empty!")
		empty_bytes_after_datasec_begin -= bytes_alloc;

		// Increase the amount of metadatas
		// and reset the new ones to empty.
		Writes writes;
		metas_us_size += amount;
		for (size_t reset = 0; reset < amount; ++ reset) {
			writes += writesMetadata(empty_metadata, metas_s_size + metas_us_size - amount + reset);
		}
		if (empty_bytes_after_datasec_begin == 0) {
			writes += writesRootRefAndCounts();
		} else {
			writes += writesRootRefAndCounts();
			writes += writesEmpty(getSectionBegin(SECTION_DATA), empty_bytes_after_datasec_begin - Nodes::Dataentry::HEADER_SIZE, false);
		}
		io.doJournalAndWrites(writes);
		HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");

	}

}

void Archive::spawnOrGetNode(Nodes::Node* node)
{
	#ifdef ENABLE_PROFILER
	Hpp::Profiler prof("Archive::spawnOrGetNode");
	#endif

	Hpp::ByteV hash = node->getHash();

	// If node already exists, then do nothing
	if (getNodeMetadataLocation(hash) >= 0) {
		return;
	}

	// Ensure flag of orphan nodes is enabled
	if (!getOrphanNodesFlag()) {
		throw Hpp::Exception("Flag of orphan nodes should be enabled, if you try to spawn completely new Nodes!");
	}

	// First ensure there is room at unsorted metadata range
	size_t empty_slot = getEmptyMetadataSlot();

	// Compress data
	#ifdef ENABLE_PROFILER
	prof.changeTask("Archive::spawnOrGetNode / Compress");
	#endif
	Hpp::ByteV data = node->getData();
	Hpp::ByteV data_compressed;
	Hpp::Compressor compressor;
	compressor.init(useroptions.compression_level);
	compressor.compress(data);
	data_compressed += compressor.read();
	data_compressed += compressor.deinit();

	// Find space for data of Node
	#ifdef ENABLE_PROFILER
	prof.changeTask("Archive::spawnOrGetNode / Find space for data");
	#endif
	size_t dataspace_begin = getSectionBegin(SECTION_DATA);
	size_t dataspace_seek = dataspace_begin;
	size_t dataspace_size = 0;
	bool dataspace_size_infinite = false;
	if (datasec_end < dataspace_seek) {
		throw Hpp::Exception("Datasection cannot have negative length!");
	}
	while (true) {
		// If there is not even header, then it
		// means infinite amount of free data.
		if (dataspace_seek == datasec_end) {
			dataspace_size_infinite = true;
			break;
		}
		// Read and parse header
		Nodes::Dataentry de = getDataentry(dataspace_seek, false);

		dataspace_seek += Nodes::Dataentry::HEADER_SIZE + de.size;

		// If this entry is empty, then
		// add it to amount of empty data
		if (de.empty) {
			dataspace_size += Nodes::Dataentry::HEADER_SIZE + de.size;
			// Check if there is now enough data
			if (dataspace_size >= 2 * Nodes::Dataentry::HEADER_SIZE + data_compressed.size()) {
				break;
			}
		}
		// If it's not empty, then start all over again.
		else {
			dataspace_begin = dataspace_seek;
			dataspace_size = 0;
		}

	}

	uint64_t original_datasec_end = datasec_end;

	// Prepare to write data of node
	#ifdef ENABLE_PROFILER
	prof.changeTask("Archive::spawnOrGetNode / Write");
	#endif
	Writes writes;
	if (dataspace_size_infinite) {
		datasec_end = dataspace_begin + Nodes::Dataentry::HEADER_SIZE + data_compressed.size();
		writes = writesData(dataspace_begin, node->getType(), data_compressed, 0);
	} else {
		HppAssert(dataspace_begin + dataspace_size <= datasec_end, "Overflow!");
		writes = writesData(dataspace_begin, node->getType(), data_compressed, dataspace_size - data_compressed.size() - Nodes::Dataentry::HEADER_SIZE);
	}
	// Prepare to write metadata of node
	Nodes::Metadata meta;
	meta.empty = false;
	meta.hash = hash;
	meta.refs = 0;
	meta.data_loc = dataspace_begin;
	meta.data_size_uncompressed = data.size();
	writes += writesMetadata(meta, metas_s_size + empty_slot);
	// Prepare to increase refrence counts of all direct children
	Nodes::Children children = node->getChildrenNodes();
	for (Nodes::Children::const_iterator children_it = children.begin();
	     children_it != children.end();
	     ++ children_it) {
		Hpp::ByteV const& child_hash = children_it->hash;
		ssize_t child_metadata_loc;
		HppAssert(child_hash.size() == NODE_HASH_SIZE, "Invalid hash size!");
		Nodes::Metadata child_metadata = getNodeMetadata(child_hash, &child_metadata_loc);
		++ child_metadata.refs;
		writes += writesMetadata(child_metadata, child_metadata_loc);
	}
	// Prepare to update end of data section
	if (original_datasec_end != datasec_end) {
		// Inform FileIO about new data end
		io.setEndOfData(datasec_end);

		writes += writesRootRefAndCounts();
	}
	// Do writing
	io.doJournalAndWrites(writes);
	HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");

	HppAssert(verifyNoDoubleMetadatas(), "Same metadata is found twice!");
}

void Archive::clearOrphanNodeRecursively(Nodes::Metadata const& metadata,
                                         size_t metadata_loc,
                                         Nodes::Type type)
{
	HppAssert(metadata.refs == 0, "Node should be orphan!");

	// Get all nodes that this node refers to.
	// Their reference count needs to be reduced.
	Hpp::ByteV node_data = getNodeData(metadata);
	Nodes::Node* node = spawnNodeFromDataAndType(node_data, type);
	Nodes::Children children = node->getChildrenNodes();
	delete node;

	NodeInfos new_orphans;

	// Prepare writing
	Writes writes;
	writes += writesClearNode(metadata, metadata_loc);
	for (Nodes::Children::const_iterator children_it = children.begin();
	     children_it != children.end();
	     ++ children_it) {
		Hpp::ByteV const& child_hash = children_it->hash;
		// Get metadata
		ssize_t child_metadata_loc;
		HppAssert(child_hash.size() == NODE_HASH_SIZE, "Invalid hash size!");
		Nodes::Metadata child_metadata = getNodeMetadata(child_hash, &child_metadata_loc);
		// Reduce reference count
		HppAssert(child_metadata.refs > 0, "Trying to reduce refrence count of child node below zero!");
		-- child_metadata.refs;
		// If reference count reaches zero, then this
		// is new orphan, and will be cleared soon.
		if (child_metadata.refs == 0) {
			NodeInfo new_orphan;
			new_orphan.metadata = child_metadata;
			new_orphan.metadata_loc = child_metadata_loc;
			new_orphan.type = children_it->type;
			new_orphans.push_back(new_orphan);
		}
		// Update metadata at disk
		writes += writesMetadata(child_metadata, child_metadata_loc);
	}

	// Do writes
	io.doJournalAndWrites(writes);
	HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");

	// Clean possible new orphans too
	for (NodeInfos::const_iterator new_orphans_it = new_orphans.begin();
	     new_orphans_it != new_orphans.end();
	     ++ new_orphans_it) {
		NodeInfo const& new_orphan = *new_orphans_it;
		clearOrphanNodeRecursively(new_orphan.metadata, new_orphan.metadata_loc, new_orphan.type);
	}

}

void Archive::setOrphanNodesFlag(bool flag)
{
	if (flag == orphan_nodes_exists) {
		return;
	}
	Writes writes = writesOrphanNodesFlag(flag);
	io.doWrites(writes);
	io.flush();
	orphan_nodes_exists = flag;
}

size_t Archive::getSectionBegin(Section sec) const
{
	size_t result = 0;
	// Archive identifier
	if (sec == SECTION_IDENTIFIER) return result;
	result += strlen(ARCHIVE_IDENTIFIER);
	// Version
	if (sec == SECTION_VERSION) return result;
	result += 1;
	// Crypto flag
	if (sec == SECTION_CRYPTO_FLAG) return result;
	result += 1;
	// Salt
	if (sec == SECTION_SALT) return result;
	if (!crypto_key.empty()) result += SALT_SIZE;
	// Password verifier
	if (sec == SECTION_PASSWORD_VERIFIER) return result;
	if (!crypto_key.empty()) result += PASSWORD_VERIFIER_SIZE;
	// Journal flag
	if (sec == SECTION_JOURNAL_FLAG) return result;
	result += 1;
	// Journal info
	if (sec == SECTION_JOURNAL_INFO) return result;
	result += 8;
	// Orphan nodes flag
	if (sec == SECTION_ORPHAN_NODES_FLAG) return result;
	result += 1;
	// Root reference, allocated metadata, end of data section
	if (sec == SECTION_ROOT_REF_AND_SIZES) return result;
	result += NODE_HASH_SIZE + 3*8;
	// Sorted metadata
	if (sec == SECTION_METADATA_SORTED) return result;
	result += Nodes::Metadata::ENTRY_SIZE * metas_s_size;
	// Unsorted metadata
	if (sec == SECTION_METADATA_UNSORTED) return result;
	result += Nodes::Metadata::ENTRY_SIZE * metas_us_size;
	// Data
	if (sec == SECTION_DATA) return result;

	HppAssert(false, "Invalid section!");
	return 0;
}

void Archive::moveData(uint64_t src, uint64_t dest,
                       uint32_t empty_b4_src, uint32_t empty_b4_dest)
{
	if (src == dest) {
		return;
	}

	// First read source data to memory (in compressed format)
	Nodes::Dataentry src_de = getDataentry(src, true);
// TODO: Fix all these assertions of empty/non-empty to real error checking!
	if (src_de.empty) {
		throw Hpp::Exception("Trying to move empty data entry!");
	}

	uint64_t original_datasec_end = datasec_end;

	// Calculate hash of this data. It needs to be extracted first.
	Hpp::ByteV data_ext;
	Hpp::Decompressor decompressor;
	decompressor.init();
	try {
		decompressor.decompress(src_de.data);
		data_ext = decompressor.read();
		data_ext += decompressor.deinit();
	}
	catch (Hpp::Exception const& e) {
		throw Hpp::Exception(std::string("Unable to extract compressed data of node! Reason: ") + e.what());
	}
	// Calculate hash
	Hpp::ByteV hash;
	Hpp::Sha512Hasher hasher;
	hasher.addData(data_ext);
	hasher.addData(Hpp::ByteV(1, uint8_t(src_de.type)));
	hasher.getHash(hash);

	// Get metadata of source node and its location
	ssize_t metadata_loc;
	HppAssert(hash.size() == NODE_HASH_SIZE, "Invalid hash size!");
	Nodes::Metadata metadata = getNodeMetadata(hash, &metadata_loc);
	metadata.data_loc = dest;

	// Calculate size of empty that source will left
	ssize_t empty_space_at_src = calculateAmountOfEmptySpace(src + Nodes::Dataentry::HEADER_SIZE + src_de.size);
	if (empty_space_at_src >= 0) {
		empty_space_at_src = src_de.size + Nodes::Dataentry::HEADER_SIZE + empty_space_at_src + (src - empty_b4_src);
	}

	// Calculate sizes and position of empties that destination will left
	size_t empty_space_before_dest = dest - empty_b4_dest;
	ssize_t empty_space_after_dest;
	if (empty_b4_src != empty_b4_dest) {
		empty_space_after_dest = calculateAmountOfEmptySpace(empty_b4_dest);
		if (empty_space_after_dest >= 0) {
			ssize_t reduce = (dest - empty_b4_dest) + Nodes::Dataentry::HEADER_SIZE + src_de.size;
			HppAssert(empty_space_after_dest == reduce || empty_space_after_dest >= reduce + ssize_t(Nodes::Dataentry::HEADER_SIZE), "Invalid amount of empty!");
			empty_space_after_dest -= reduce;
		}
	} else {
		ssize_t empty_space_after_src = calculateAmountOfEmptySpace(src + Nodes::Dataentry::HEADER_SIZE + src_de.size);
		if (empty_space_after_src < 0) {
			empty_space_after_dest = -1;
		} else if (src > dest) {
			empty_space_after_dest = empty_space_after_src;
		} else {
			empty_space_after_dest = empty_space_after_src - (dest - src);
		}
	}

	// Prepare to write changes to disk.
	Writes writes;

	// Prepare metadata update
	writes += writesMetadata(metadata, metadata_loc);

	// Prepare clearing of src. Do not perform this, if src empty is same as dest empty
	if (empty_b4_src != empty_b4_dest) {
		if (empty_space_at_src < 0) {
			datasec_end = empty_b4_src;
		} else {
			HppAssert(empty_space_at_src >= (ssize_t)Nodes::Dataentry::HEADER_SIZE, "Too little amount of empty data! Header does not fit!");
			HppAssert(empty_b4_src + empty_space_at_src <= (ssize_t)datasec_end, "Overflow!");
			writes += writesEmpty(empty_b4_src, empty_space_at_src - Nodes::Dataentry::HEADER_SIZE, true);
		}
	}

	// Write data and empty after it
	if (empty_space_after_dest < 0) {
		datasec_end = dest + Nodes::Dataentry::HEADER_SIZE + src_de.size;
		writes += writesData(dest, src_de.type, src_de.data, 0);
		HppAssert(empty_b4_src == empty_b4_dest || empty_space_at_src >= 0, "Both empties try to write the data ending!");
	} else {
		HppAssert(datasec_end > dest + Nodes::Dataentry::HEADER_SIZE + src_de.data.size() + empty_space_after_dest, "There should be more empty space!");
		writes += writesData(dest, src_de.type, src_de.data, empty_space_after_dest);
	}

	// Clear data before dest
	if (empty_space_before_dest != 0) {
		HppAssert(empty_b4_dest + empty_space_before_dest <= datasec_end, "Overflow!");
		HppAssert(empty_space_before_dest >= Nodes::Dataentry::HEADER_SIZE, "Fail!");
		writes += writesEmpty(empty_b4_dest, empty_space_before_dest - Nodes::Dataentry::HEADER_SIZE, false);
	}

	// If datasection end was changed, then write it too
	if (original_datasec_end != datasec_end) {
		// Inform FileIO about new data end
		io.setEndOfData(datasec_end);

		writes += writesRootRefAndCounts();
	}

	// Do writes
	io.doJournalAndWrites(writes);
	HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");
}

void Archive::readFileHierarchiesAsFolderChildren(Nodes::Folder::Children& result, Paths const& sources)
{
	// Ensure no source has the same name
	std::set< std::string > source_names;
	for (Paths::const_iterator sources_it = sources.begin();
	     sources_it != sources.end();
	     ++ sources_it) {
		Hpp::Path const& source = *sources_it;
		std::string source_name = source.getFilename();
		if (source_names.find(source_name) != source_names.end()) {
			throw Hpp::Exception("Unable to process sources that have same name!");
		}
		source_names.insert(source_name);
	}

	result.clear();

// TODO: What if source has disappeared?
	for (Paths::const_iterator sources_it = sources.begin();
	     sources_it != sources.end();
	     ++ sources_it) {
		Hpp::Path const& source = *sources_it;

		Hpp::ByteV source_hash;
		Nodes::FsType source_fstype;
		readFileHierarchy(source_hash, source_fstype, source);

		std::string source_name = source.getFilename();
		Nodes::FsMetadata source_fsmetadata = Nodes::FsMetadata(source);

		Nodes::Folder::Child new_result;
		new_result.hash = source_hash;
		new_result.type = source_fstype;
		new_result.fsmetadata = source_fsmetadata;

		result[source_name] = new_result;
	}
}

void Archive::readFileHierarchy(Hpp::ByteV& result_hash, Nodes::FsType& result_fstype, Hpp::Path const& source)
{
	if (useroptions.verbose) {
		(*useroptions.verbose) << source.toString() << std::endl;
	}

	// Symlink
// TODO: Should symlinks be considered as normal, empty files with symlink target as metadata? This would be more multiplatform.
	if (source.isLink()) {
		Nodes::Symlink new_symlink(source.linkTarget());
		spawnOrGetNode(&new_symlink);
		result_hash = new_symlink.getHash();
		result_fstype = Nodes::FSTYPE_SYMLINK;
		return;
	}

	// Folder
	if (source.isDir()) {
		Nodes::Folder new_folder;
		// Add children to Folder
		Hpp::Path::DirChildren children;
		source.listDir(children);
		for (Hpp::Path::DirChildren::const_iterator children_it = children.begin();
		     children_it != children.end();
		     ++ children_it) {
			Hpp::Path::DirChild const& child = *children_it;
			Hpp::Path child_path = source / child.name;

			// Get type. Skip unknown files
			if (child.type == Hpp::Path::UNKNOWN) {
				continue;
			}
			Nodes::FsType child_type;
			if (child.type == Hpp::Path::FILE) {
				child_type = Nodes::FSTYPE_FILE;
			} else if (child.type == Hpp::Path::DIRECTORY) {
				child_type = Nodes::FSTYPE_FOLDER;
			} else {
				HppAssert(child.type == Hpp::Path::SYMLINK, "Wrong type!");
				child_type = Nodes::FSTYPE_SYMLINK;
			}

			// Get hash and metadata and form Node from them.
			Nodes::FsType dummy;
			Hpp::ByteV child_hash;
			Nodes::FsMetadata child_fsmetadata;
			try {
				readFileHierarchy(child_hash, dummy, child_path);
				child_fsmetadata = Nodes::FsMetadata(child_path);
			}
			catch (Hpp::Exception) {
				// This error is most likely caused by a living
				// file system. Maybe user just removed some
				// file, while backup was being ran. This is
				// not a serious problem, so just ignore it.
				continue;
			}

			// If there was not any problems, then add child
			new_folder.setChild(child.name, child_type, child_hash, child_fsmetadata);

		}
		// Spawn and return Node
		spawnOrGetNode(&new_folder);
		result_hash = new_folder.getHash();
		result_fstype = Nodes::FSTYPE_FOLDER;
		return;
	}

	// File
	if (source.isFile()) {
		Nodes::File new_file;

		// Convert file contents into datablocks.
		// First open file and get its size.
		std::ifstream source_file(source.toString().c_str(), std::ios_base::binary);
		source_file.seekg(0, std::ios_base::end);
		size_t source_file_left = source_file.tellg();
		source_file.seekg(0, std::ios_base::beg);

		// Read file
		Hpp::ByteV readbuf(STATIC_DATABLOCK_SIZE, 0);
		while (source_file_left > 0) {
			// Read bytes
			size_t read_amount = std::min(source_file_left, STATIC_DATABLOCK_SIZE);
			source_file.read((char*)&readbuf[0], read_amount);
			readbuf.resize(read_amount);
			source_file_left -= read_amount;
			// Spawn new Datablock
			Nodes::Datablock new_datablock(readbuf);
			spawnOrGetNode(&new_datablock);
			// Add datablock to file
			new_file.addDatablock(new_datablock.getHash(), read_amount);
		}

		spawnOrGetNode(&new_file);
		result_hash = new_file.getHash();
		result_fstype = Nodes::FSTYPE_FILE;
		return;
	}

	throw Hpp::Exception("Unable to archive " + source.toString() + " because it has invalid type!");
}

void Archive::extractRecursively(Hpp::ByteV const& hash,
                                 Nodes::FsMetadata const& fsmetadata,
                                 Hpp::Path const& target)
{
	if (useroptions.verbose) {
		(*useroptions.verbose) << target.toString() << std::endl;
	}

	Nodes::Metadata metadata = getNodeMetadata(hash);

	Nodes::Dataentry de = getDataentry(metadata.data_loc, true, true);

	if (de.type == Nodes::TYPE_FOLDER) {
		Nodes::Folder folder(de.data);

		target.ensureDirExists();
// TODO: Apply FsMetadata!
(void)fsmetadata;

		// Extract children
		for (std::string child = folder.getFirstChild();
		     child != "";
		     child = folder.getNextChild(child)) {
			Hpp::ByteV child_hash = folder.getChildHash(child);
			Nodes::FsMetadata child_fsmetadata = folder.getChildFsMetadata(child);
			extractRecursively(child_hash, child_fsmetadata, target / child);
		}
	}
	else if (de.type == Nodes::TYPE_FILE) {
		Nodes::File file(de.data);

		std::ofstream file_file(target.toString().c_str(), std::ios_base::binary);

		for (size_t datablock_id = 0;
		     datablock_id < file.getNumOfDatablocks();
		     ++ datablock_id) {
			Nodes::File::Datablock datablock = file.getDatablock(datablock_id);

			// Get data of datablock
			Hpp::ByteV datablock_data = getNodeData(datablock.hash);
			HppAssert(datablock_data.size() == datablock.size, "Data has invalid size!");

			file_file.write((char const*)&datablock_data[0], datablock.size);

		}

		file_file.close();

// TODO: Apply FsMetadata!
(void)fsmetadata;
	}
	else if (de.type == Nodes::TYPE_SYMLINK) {
		Nodes::Symlink symlink(de.data);
(void)symlink;
// TODO: Code this!
HppAssert(false, "Extracting of symlink not implemented yet!");
	}
	else {
		throw Hpp::Exception("Trying to extract node that has invalid type!");
	}

}

Hpp::ByteV Archive::generateCryptoKey(std::string const& password, Hpp::ByteV const& salt)
{
	Hpp::Sha256Hasher hasher;
	hasher.addData(password);
	hasher.addData(salt);
	Hpp::ByteV result;
	hasher.getHash(result);
	return result;
}

Nodes::Node* Archive::spawnNodeFromDataAndType(Hpp::ByteV const& data, Nodes::Type type)
{
	switch (type) {

	case Nodes::TYPE_DATABLOCK:
		return new Nodes::Datablock(data);

	case Nodes::TYPE_FILE:
		return new Nodes::File(data);

	case Nodes::TYPE_FOLDER:
		return new Nodes::Folder(data);

	case Nodes::TYPE_SYMLINK:
		return new Nodes::Symlink(data);

	default:
		HppAssert(false, "Invalid type!");
		return NULL;

	}
}

Nodes::Node* Archive::spawnNodeFromDataentry(Nodes::Dataentry const& dataentry)
{
	HppAssert(!dataentry.empty, "Unable to spawn Node from empty Dataentry!");
	return spawnNodeFromDataAndType(dataentry.data, dataentry.type);
}
