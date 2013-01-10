#include "archive.h"

#include "nodes/datablock.h"
#include "nodes/file.h"
#include "nodes/symlink.h"
#include "exceptions/notfound.h"
#include "exceptions/alreadyexists.h"
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
#ifdef ENABLE_FILEIO_CACHE
io(useroptions.writecache_size, useroptions.readcache_size),
#else
io(useroptions.writecache_size),
#endif
nodes_size(0),
searchtree_begin(0),
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

	io.initWrite(false);

	// Identifier
	size_t const IDENTIFIER_LEN = strlen(ARCHIVE_IDENTIFIER);
	io.writeChunk(0, Hpp::ByteV(ARCHIVE_IDENTIFIER, ARCHIVE_IDENTIFIER + IDENTIFIER_LEN), false);

	// Version
	io.writeChunk(IDENTIFIER_LEN, Hpp::ByteV(1, 0), false);

	// Crypto flag and possible salt
	Hpp::ByteV salt;
	if (password.empty()) {
		io.writeChunk(IDENTIFIER_LEN + 1, Hpp::ByteV(1, 0), false);
	} else {
		io.writeChunk(IDENTIFIER_LEN + 1, Hpp::ByteV(1, 1), false);
		salt = Hpp::randomSecureData(SALT_SIZE);
		io.writeChunk(IDENTIFIER_LEN + 2, salt, false);
	}

	// If password is used, then generate crypto key and password verifier
	if (!password.empty()) {
		crypto_key = generateCryptoKey(password, salt);

		// Inform FileIO about this
		io.enableCrypto(crypto_key);

		// Create new password verifier and write it to the disk.
		Hpp::ByteV crypto_password_verifier = Hpp::randomSecureData(PASSWORD_VERIFIER_SIZE / 2);
		writePasswordVerifier(crypto_password_verifier);
	}

	io.initAndWriteJournalFlagToFalse();

	io.writeChunk(getSectionBegin(SECTION_JOURNAL_INFO), Hpp::uInt64ToByteV(Hpp::randomNBitInt(64)));

	// Initialize rest of header with fake root reference and zero metadata
	// amounts. After this, everything is correct, except root reference.
	root_ref = Hpp::ByteV(64, 0);
	nodes_size = 0;
	searchtree_begin = 0;
	datasec_end = getSectionBegin(SECTION_DATA);

	// Inform FileIO about new data end
	io.setEndOfData(datasec_end);

	writeRootRefAndCounts();

	// Enable flag of orphan nodes. New
	// Nodes cannot be spawned without this.
	setOrphanNodesFlag(true);

	io.deinitWrite();

	// Spawn empty Folder node to serve as root node
	Nodes::Folder folder;
	spawnOrGetNode(&folder);
	root_ref = folder.getHash();

	io.initWrite(false);
	writeSetNodeRefs(root_ref, 1);
	writeRootRefAndCounts();

	// Mark no orphans
	setOrphanNodesFlag(false);

	// Flush writes
	io.deinitWrite();

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
	catch (Exceptions::NotFound) {
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
	io.initWrite(false);
	setOrphanNodesFlag(true);
	io.deinitWrite();

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
		HppAssert(old_root != root_ref, "Trying to remove root node!");
		clearOrphanNodeRecursively(old_root, Nodes::TYPE_FOLDER);
	}

	io.initWrite(false);
	setOrphanNodesFlag(orphan_nodes_flag_before);
	io.deinitWrite();
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
	catch (Exceptions::NotFound) {
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
	io.initWrite(false);
	setOrphanNodesFlag(true);
	io.deinitWrite();

	Hpp::ByteV root_now = root_ref;

	ByteVs nodes_to_remove;

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
	for (ByteVs::const_iterator nodes_to_remove_it = nodes_to_remove.begin();
	     nodes_to_remove_it != nodes_to_remove.end();
	     ++ nodes_to_remove_it) {
		Hpp::ByteV const& node_to_remove = *nodes_to_remove_it;

		ssize_t metadata_loc = getNodeMetadataLocation(node_to_remove);
		if (metadata_loc >= 0) {
			Nodes::Metadata metadata = getNodeMetadata(metadata_loc);
			if (metadata.refs == 0) {
				HppAssert(node_to_remove != root_ref, "Trying to remove root node!");
				clearOrphanNodeRecursively(node_to_remove, Nodes::TYPE_FOLDER);
			}
		}

	}

	io.initWrite(false);
	setOrphanNodesFlag(orphan_nodes_flag_before);
	io.deinitWrite();
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
			throw Exceptions::AlreadyExists("Unable to create directory, because \"" + path.toString() + "\" already exists!");
		}
	}

// TODO: Ensure no path is given twice

	// The following operations will create new Nodes,
	// that will be orphans at first. Because of this,
	// the appropriate flag needs to be toggled on.
	bool orphan_nodes_flag_before = getOrphanNodesFlag();
	io.initWrite(false);
	setOrphanNodesFlag(true);
	io.deinitWrite();

	Hpp::ByteV root_now = root_ref;

	ByteVs nodes_to_remove;

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
	for (ByteVs::const_iterator nodes_to_remove_it = nodes_to_remove.begin();
	     nodes_to_remove_it != nodes_to_remove.end();
	     ++ nodes_to_remove_it) {
		Hpp::ByteV const& node_to_remove = *nodes_to_remove_it;

		ssize_t metadata_loc = getNodeMetadataLocation(node_to_remove);
		if (metadata_loc >= 0) {
			Nodes::Metadata metadata = getNodeMetadata(metadata_loc);
			if (metadata.refs == 0) {
				HppAssert(node_to_remove != root_ref, "Trying to remove root node!");
				clearOrphanNodeRecursively(node_to_remove, Nodes::TYPE_FOLDER);
			}
		}

	}

	io.initWrite(false);
	setOrphanNodesFlag(orphan_nodes_flag_before);
	io.deinitWrite();
}

void Archive::finishPossibleInterruptedJournal(void)
{
	if (io.finishPossibleInterruptedJournal()) {

		// Because state of file has changed, it needs to be loaded again.
		loadStateFromFile("");

		HppAssert(verifyDataentriesAreValid(), "Data is failed after applying of interrupted journal!");

	}
}

void Archive::removePossibleOrphans(void)
{
	bool all_orphans_known = false;
	ByteVs orphans;
	std::vector< Nodes::Type > types;
	do {
		// Gather as many orphans as possible
		orphans.clear();
		types.clear();
		size_t metadata_ofs = 0;
		while (orphans.size() < REMOVE_ORPHANS_MAX_HASHES_IN_MEMORY) {
			Nodes::Metadata metadata = getMetadata(metadata_ofs);
			if (metadata.refs == 0) {
				orphans.push_back(metadata.hash);
				Nodes::Dataentry dataentry = getDataentry(metadata.data_loc, false);
				types.push_back(dataentry.type);
			}
			++ metadata_ofs;
			if (metadata_ofs == nodes_size) {
				all_orphans_known = true;
				break;
			}
		}

		// Now go all orphans through and remove them
		for (size_t orphan_id = 0;
		     orphan_id < orphans.size();
		     ++ orphan_id) {
			Hpp::ByteV const& hash = orphans[orphan_id];
			Nodes::Type type = types[orphan_id];
			clearOrphanNodeRecursively(hash, type);
		}

	} while (!all_orphans_known);

	// Mark no orphans left. Journal is not
	// needed, as this writes to only one byte.
	io.initWrite(false);
	setOrphanNodesFlag(false);
	io.deinitWrite();
}

void Archive::optimizeMetadata(void)
{
// TODO: Balance search tree!
}

void Archive::shrinkFileToMinimumPossible(void)
{
	io.shrinkFileToMinimumPossible();
}

Hpp::ByteV Archive::getPasswordVerifier(void)
{
	return io.readPart(getSectionBegin(SECTION_PASSWORD_VERIFIER), PASSWORD_VERIFIER_SIZE / 2);
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

size_t Archive::getDataareaSize(void)
{
	return datasec_end - getSectionBegin(SECTION_DATA);
}

size_t Archive::getEmptyBytesAtDataarea(void)
{
	size_t result = 0;
	size_t dataentry_loc = getSectionBegin(SECTION_DATA);
	while (dataentry_loc != datasec_end) {
		if (dataentry_loc > datasec_end) {
			throw Hpp::Exception("Dataentry overflows data-area!");
		}
		Nodes::Dataentry de = getDataentry(dataentry_loc, false);
		if (de.empty) {
			result += Nodes::Dataentry::HEADER_SIZE + de.size;
		}
		dataentry_loc += Nodes::Dataentry::HEADER_SIZE + de.size;
	}
	return result;
}

bool Archive::pathExists(Hpp::Path const& path)
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

Archive::SearchtreeDepthAnalysis Archive::getSearchtreeDepths(void)
{
	SearchtreeDepthAnalysis result;

	analyseSearchtreeDepth(result, searchtree_begin, 0);

	return result;
}

bool Archive::verifyDataentriesAreValid(bool throw_exception)
{
	size_t check_loc = getSectionBegin(SECTION_DATA);
	size_t nodes_size_check = 0;
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
			++ nodes_size_check;
		}

		check_loc += Nodes::Dataentry::HEADER_SIZE + check_de.size;
	}

	if (nodes_size != nodes_size_check) {
		if (throw_exception) {
			throw Hpp::Exception("Number of nodes in metadatas(" + Hpp::sizeToStr(nodes_size) + ") and in dataentries(" + Hpp::sizeToStr(nodes_size_check) + ") do not match!");
		}
		return false;
	}

	return true;
}

bool Archive::verifyNoDoubleMetadatas(bool throw_exception)
{
// TODO: Now this may use infinite amount of memory! Fix it!
	std::set< Hpp::ByteV > hashes;
	for (size_t metadata_id = 0;
	     metadata_id < nodes_size;
	     ++ metadata_id) {
		Nodes::Metadata metadata = getNodeMetadata(metadata_id);
		Hpp::ByteV const& hash = metadata.hash;
		if (!hashes.insert(hash).second) {
			if (throw_exception) {
				throw Hpp::Exception("Hash " + Hpp::byteVToHexV(hash) + " exists multiple times on metadatas!");
			}
			return false;
		}
	}

	return true;
}

bool Archive::verifyReferences(bool throw_exception)
{
	size_t metadata_ofs = 0;
	while (metadata_ofs < nodes_size) {

		// Pick some Nodes for reference count check
		std::map< Hpp::ByteV, uint32_t > refs;
		while (refs.size() < VERIFY_REFERENCES_MAX_CHECK_AMOUNT_PER_ITERATION && metadata_ofs < nodes_size) {
			Nodes::Metadata metadata = getNodeMetadata(metadata_ofs);
			++ metadata_ofs;
			refs[metadata.hash] = metadata.refs;
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

bool Archive::verifyMetadatas(bool throw_exception)
{
	if (nodes_size == 0) {
		return true;
	}

	size_t datasec_begin = getSectionBegin(SECTION_DATA);

	for (size_t metadata_loc = 0;
	     metadata_loc < nodes_size;
	     ++ metadata_loc) {
		Nodes::Metadata metadata = getNodeMetadata(metadata_loc);
		// Ensure dataentry does not underflow
		if (metadata.data_loc < datasec_begin) {
			if (throw_exception) {
				throw Hpp::Exception("Dataentry underflow for Metadata #" + Hpp::sizeToStr(metadata_loc) + "!");
			}
			return false;
		}
		// Ensure dataentry does not overflow
		if (metadata.data_loc + Nodes::Dataentry::HEADER_SIZE > datasec_end) {
			if (throw_exception) {
				throw Hpp::Exception("Dataentry header overflows for Metadata #" + Hpp::sizeToStr(metadata_loc) + "!");
			}
			return false;
		}
		Nodes::Dataentry de = getDataentry(metadata.data_loc, false);
		if (metadata.data_loc + Nodes::Dataentry::HEADER_SIZE + uint64_t(de.size) > datasec_end) {
			if (throw_exception) {
				throw Hpp::Exception("Dataentry overflows for Metadata #" + Hpp::sizeToStr(metadata_loc) + "!");
			}
			return false;
		}
		// Ensure parents and children are not pointed outside range of nodes
		if (metadata.parent != Nodes::Metadata::NULL_REF && metadata.parent >= nodes_size) {
			if (throw_exception) {
				throw Hpp::Exception("Metadata #" + Hpp::sizeToStr(metadata_loc) + " has parent outside range of nodes!");
			}
			return false;
		}
		if (metadata.child_small != Nodes::Metadata::NULL_REF && metadata.child_small >= nodes_size) {
			if (throw_exception) {
				throw Hpp::Exception("Metadata #" + Hpp::sizeToStr(metadata_loc) + " has smaller child outside range of nodes!");
			}
			return false;
		}
		if (metadata.child_big != Nodes::Metadata::NULL_REF && metadata.child_big >= nodes_size) {
			if (throw_exception) {
				throw Hpp::Exception("Metadata #" + Hpp::sizeToStr(metadata_loc) + " has bigger child outside range of nodes!");
			}
			return false;
		}
		// Ensure parents refer to their children and viseversa
		if (metadata.parent != Nodes::Metadata::NULL_REF) {
			Nodes::Metadata parent = getNodeMetadata(metadata.parent);
			if (parent.child_small != metadata_loc && parent.child_big != metadata_loc) {
				if (throw_exception) {
					throw Hpp::Exception("Parent(" + Hpp::sizeToStr(metadata.parent) + ") of metadata #" + Hpp::sizeToStr(metadata_loc) + " does not point to this metadata!");
				}
				return false;
			}
		}
		if (metadata.child_small != Nodes::Metadata::NULL_REF) {
			Nodes::Metadata child = getNodeMetadata(metadata.child_small);
			if (child.parent != metadata_loc) {
				if (throw_exception) {
					throw Hpp::Exception("Smaller child(" + Hpp::sizeToStr(metadata.child_small) + ") of metadata #" + Hpp::sizeToStr(metadata_loc) + " does not point to this metadata, but to " + Nodes::Metadata::searchtreeRefToString(child.parent) + "!");
				}
				return false;
			}
		}
		if (metadata.child_big != Nodes::Metadata::NULL_REF) {
			Nodes::Metadata child = getNodeMetadata(metadata.child_big);
			if (child.parent != metadata_loc) {
				if (throw_exception) {
					throw Hpp::Exception("Smaller child(" + Hpp::sizeToStr(metadata.child_big) + ") of metadata #" + Hpp::sizeToStr(metadata_loc) + " does not point to this metadata, but to " + Nodes::Metadata::searchtreeRefToString(child.parent) + "!");
				}
				return false;
			}
		}
		// First metadata in searchtree should have
		// no parent and all others should have
		if (metadata.parent == Nodes::Metadata::NULL_REF && metadata_loc != searchtree_begin) {
			if (throw_exception) {
				throw Hpp::Exception("Metadata #" + Hpp::sizeToStr(metadata_loc) + " has no parent!");
			}
			return false;
		}
		if (metadata.parent != Nodes::Metadata::NULL_REF && metadata_loc == searchtree_begin) {
			if (throw_exception) {
				throw Hpp::Exception("First metadata of searchtree should not have parent!");
			}
			return false;
		}
	}

	// Verify all metadatas are in the search tree
	size_t metadatas_met = 0;
	std::list< Nodes::Metadata > stack;
	stack.push_back(getNodeMetadata(searchtree_begin));
	while (!stack.empty()) {
		if (stack.back().child_small != Nodes::Metadata::NULL_REF) {
			Nodes::Metadata new_check = getNodeMetadata(stack.back().child_small);
			stack.back().child_small = Nodes::Metadata::NULL_REF;
			stack.push_back(new_check);
		} else if (stack.back().child_big != Nodes::Metadata::NULL_REF) {
			Nodes::Metadata new_check = getNodeMetadata(stack.back().child_big);
			stack.back().child_big = Nodes::Metadata::NULL_REF;
			stack.push_back(new_check);
		} else {
			++ metadatas_met;
			stack.pop_back();
		}
	}
	if (metadatas_met < nodes_size) {
		if (throw_exception) {
			throw Hpp::Exception("There are some metadata nodes that are not reachable from the searchtree!");
		}
		return false;
	} else if (metadatas_met > nodes_size) {
		if (throw_exception) {
			throw Hpp::Exception("There are more metadatas reachable from the searchtree than should be!");
		}
		return false;
	}

	return true;
}

bool Archive::verifyRootNodeExists(bool throw_exception)
{
	ssize_t rootnode_loc = getNodeMetadataLocation(root_ref);
	if (rootnode_loc < 0) {
		if (throw_exception) {
			throw Hpp::Exception("Root node does not exist!");
		}
		return false;
	}
	Nodes::Metadata rootnode = getNodeMetadata(rootnode_loc);
	if (rootnode.refs == 0) {
		if (throw_exception) {
			throw Hpp::Exception("There is zero references to root node!");
		}
		return false;
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

			Hpp::ByteV crypto_password_verifier = io.readPart(getSectionBegin(SECTION_PASSWORD_VERIFIER), PASSWORD_VERIFIER_SIZE);
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
	nodes_size = Hpp::cStrToUInt64(&root_refs_and_sizes[NODE_HASH_SIZE]);
	searchtree_begin = Hpp::cStrToUInt64(&root_refs_and_sizes[NODE_HASH_SIZE + 8]);
	datasec_end = Hpp::cStrToUInt64(&root_refs_and_sizes[NODE_HASH_SIZE + 16]);

	// Inform FileIO about new data end
	io.setEndOfData(datasec_end);

	// Check if journal or orphan nodes exists
	io.readJournalflagState();
	orphan_nodes_exists = (io.readPart(getSectionBegin(SECTION_ORPHAN_NODES_FLAG), 1)[0] >= 128);

}

uint8_t Archive::findMetadataFromSearchtree(Nodes::Metadata* result_metadata, uint64_t* result_metadata_loc, Hpp::ByteV const& hash, uint64_t begin_loc)
{
	#ifdef ENABLE_PROFILER
	Hpp::Profiler prof("Archive::findMetadataFromSearchtree");
	#endif

	if (nodes_size == 0) {
		return 3;
	}

	uint64_t find_loc = begin_loc;

	while (true) {
		HppAssert(find_loc != Nodes::Metadata::NULL_REF, "Trying to find from NULL_REF!");
		HppAssert(find_loc < nodes_size, "Overflow!");
		Nodes::Metadata meta = getNodeMetadata(find_loc);
		// Ensure metadata does not point to itself
		if (meta.parent == find_loc) {
			throw Hpp::Exception("Metadata #" + Hpp::sizeToStr(find_loc) + " claims its parent is itself!");
		}
		if (meta.child_small == find_loc) {
			throw Hpp::Exception("Metadata #" + Hpp::sizeToStr(find_loc) + " claims its smaller child is itself!");
		}
		if (meta.child_big == find_loc) {
			throw Hpp::Exception("Metadata #" + Hpp::sizeToStr(find_loc) + " claims its bigger child is itself!");
		}
		if (meta.parent != Nodes::Metadata::NULL_REF && meta.parent >= nodes_size) {
			throw Hpp::Exception("Metadata #" + Hpp::sizeToStr(find_loc) + " has parent outside range of nodes!");
		}
		if (meta.child_small != Nodes::Metadata::NULL_REF && meta.child_small >= nodes_size) {
			throw Hpp::Exception("Metadata #" + Hpp::sizeToStr(find_loc) + " has smaller child outside range of nodes!");
		}
		if (meta.child_big != Nodes::Metadata::NULL_REF && meta.child_big >= nodes_size) {
			throw Hpp::Exception("Metadata #" + Hpp::sizeToStr(find_loc) + " has bigger child outside range of nodes!");
		}
		// Check if this is the hash
		if (meta.hash == hash) {
			if (result_metadata) {
				*result_metadata = meta;
			}
			if (result_metadata_loc) {
				*result_metadata_loc = find_loc;
			}
			return 0;
		}
		// Check if correct metadata should be
		// found from among smaller children
		if (hash < meta.hash) {
			if (meta.child_small == Nodes::Metadata::NULL_REF) {
				if (result_metadata) {
					*result_metadata = meta;
				}
				if (result_metadata_loc) {
					*result_metadata_loc = find_loc;
				}
				return 1;
			}
			find_loc = meta.child_small;
		} else {
			if (meta.child_big == Nodes::Metadata::NULL_REF) {
				if (result_metadata) {
					*result_metadata = meta;
				}
				if (result_metadata_loc) {
					*result_metadata_loc = find_loc;
				}
				return 2;
			}
			find_loc = meta.child_big;
		}
	}
}

ssize_t Archive::getNodeMetadataLocation(Hpp::ByteV const& hash)
{
	if (nodes_size == 0) {
		return -1;
	}

	uint64_t loc;
	uint8_t find_type = findMetadataFromSearchtree(NULL, &loc, hash, searchtree_begin);
	if (find_type == 0) {
		return loc;
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
	if (metadata_loc >= nodes_size) {
		throw Hpp::Exception("Metadata offset overflow!");
	}

	size_t metadata_loc_abs = getSectionBegin(SECTION_METADATA) + metadata_loc * Nodes::Metadata::ENTRY_SIZE;

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
	uint64_t empty_space = 0;
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
			throw Exceptions::NotFound("Path does not exist!");
		}

		Nodes::Folder subfolder(getNodeData(parent_folder.getChildHash(subfolder_name)));

		result.push_back(subfolder);
		parent_folder = subfolder;
	}

	return result;
}

size_t Archive::findEmptyData(size_t size, ssize_t prevent_results_before)
{
	#ifdef ENABLE_PROFILER
	Hpp::Profiler prof("Archive::findEmptyData");
	#endif

	// If there are any nodes, then search empty data among them first.
	if (nodes_size > 0) {
		// First pick random metadata. The position of its data is
		// used as a starting position for seeking an empty space.
		size_t metadata_loc = Hpp::randomInt(0, nodes_size - 1);

		uint64_t search = getNodeMetadata(metadata_loc).data_loc;
		Nodes::Dataentry de = getDataentry(search, false);
		search += Nodes::Dataentry::HEADER_SIZE + de.size;

		size_t tries_left = FIND_EMPTY_DATA_TRIES;
		while (tries_left > 0) {
			-- tries_left;

			// Calculate how much there is empty space here
			ssize_t empty_here = calculateAmountOfEmptySpace(search);

			// If we are at the end of data, then leave this loop.
			// There is special routine for this case after it.
			if (empty_here < 0) {
				break;
			}

			if (empty_here < ssize_t(size)) {
				// There was not enough space
			} else if (empty_here - size != 0 && empty_here - size < Nodes::Dataentry::HEADER_SIZE) {
				// There would not be enough empty
				// space after this result.
			} else if (ssize_t(search) < prevent_results_before) {
				// This result would be at the protected area
			} else if (search - prevent_results_before != 0 && search - prevent_results_before < Nodes::Dataentry::HEADER_SIZE) {
				// This result would be at the protected area
			} else {
				// This is valid result!
				return search;
			}

			// Read next dataentry
			search += empty_here;
			de = getDataentry(search, false);
			search += Nodes::Dataentry::HEADER_SIZE + de.size;

		}

	}

	// Choose end of data, but remember to check possible protected begin.
	size_t result = datasec_end;
	// Check if beginning needs to be protected
	if (prevent_results_before >= 0) {
		if (ssize_t(result) < prevent_results_before) {
			result = prevent_results_before;
		} else if (result - prevent_results_before != 0 && result - prevent_results_before < Nodes::Dataentry::HEADER_SIZE) {
			result = prevent_results_before + Nodes::Dataentry::HEADER_SIZE;
		}
		if (result > datasec_end && result - datasec_end < Nodes::Dataentry::HEADER_SIZE) {
			result = datasec_end + Nodes::Dataentry::HEADER_SIZE;
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
	catch (Exceptions::NotFound) {
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
		throw Exceptions::AlreadyExists("Unable to create new folder because there is already something with the same name!");
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
		#ifndef NDEBUG
		Nodes::Metadata root_metadata = getNodeMetadata(root_ref);
		HppAssert(root_metadata.refs > 0, "Trying to replace root node with old root that has zero references!");
		#endif
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
	io.initWrite(true);
	writeRootRefAndCounts();
	writeMetadata(metadata_old, metadata_old_loc);
	writeMetadata(metadata_new, metadata_new_loc);

	// Write
	io.deinitWrite();
	HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");

}

void Archive::writePasswordVerifier(Hpp::ByteV const& crypto_password_verifier)
{
	if (crypto_key.empty()) {
		throw Hpp::Exception("Writing password verifier requires cryptokey set!");
	}

	Hpp::ByteV part;
	part.reserve(PASSWORD_VERIFIER_SIZE);
	part += crypto_password_verifier;
	part += crypto_password_verifier;

	io.writeChunk(getSectionBegin(SECTION_PASSWORD_VERIFIER), part);
}

void Archive::writeOrphanNodesFlag(bool orphans_exists)
{
	Hpp::ByteV flag_serialized;
	if (orphans_exists) {
		flag_serialized.push_back(Hpp::randomInt(128, 255));
	} else {
		flag_serialized.push_back(Hpp::randomInt(0, 127));
	}

	io.writeChunk(getSectionBegin(SECTION_ORPHAN_NODES_FLAG), flag_serialized);
}

void Archive::writeSetNodeRefs(Hpp::ByteV const& hash, uint32_t refs)
{
	HppAssert(hash.size() == NODE_HASH_SIZE, "Invalid hash size!");
	ssize_t metadata_loc;
	Nodes::Metadata meta = getNodeMetadata(hash, &metadata_loc);
	meta.refs = refs;
	writeMetadata(meta, metadata_loc);
}

void Archive::writeMetadata(Nodes::Metadata const& meta, size_t metadata_loc)
{
	HppAssert(metadata_loc != Nodes::Metadata::NULL_REF, "Trying to write metadata to NULL_REF!");
	HppAssert(meta.parent != metadata_loc, "Trying to write metadata that has itself as parent!");
	HppAssert(meta.child_small != metadata_loc, "Trying to write metadata that has itself as smaller child!");
	HppAssert(meta.child_big != metadata_loc, "Trying to write metadata that has itself as bigger child!");
	HppAssert(metadata_loc < nodes_size, "Metadata offset too big!");
	size_t begin = getSectionBegin(SECTION_METADATA);
	io.writeChunk(begin + metadata_loc * Nodes::Metadata::ENTRY_SIZE, meta.serialize());
}

void Archive::writeRootRefAndCounts(void)
{
	HppAssert(root_ref.size() == NODE_HASH_SIZE, "Root reference has invalid size!");

	Hpp::ByteV data;
	data.reserve(ROOT_REF_AND_SIZES_SIZE);
	data += root_ref;
	data += Hpp::uInt64ToByteV(nodes_size);
	data += Hpp::uInt64ToByteV(searchtree_begin);
	data += Hpp::uInt64ToByteV(datasec_end);

	HppAssert(data.size() + getSectionBegin(SECTION_ROOT_REF_AND_SIZES) == getSectionBegin(SECTION_METADATA), "Fail!");
	io.writeChunk(getSectionBegin(SECTION_ROOT_REF_AND_SIZES), data);
}

void Archive::writeData(uint64_t begin, Nodes::Type type, Hpp::ByteV const& data, uint32_t empty_space_after)
{
	HppAssert(begin + Nodes::Dataentry::HEADER_SIZE + data.size() + empty_space_after <= datasec_end, "Trying to write data after datasection!");

	Hpp::ByteV size_chunk = Hpp::uInt32ToByteV(data.size() & Nodes::Dataentry::MASK_DATASIZE);
	size_chunk[0] |= uint8_t(type) << 5;
	io.writeChunk(begin, size_chunk);
	io.writeChunk(begin + Nodes::Dataentry::HEADER_SIZE, data);

	if (empty_space_after > 0) {
		HppAssert(empty_space_after >= Nodes::Dataentry::HEADER_SIZE, "Empty after data must be zero, or at least four!");
		io.writeChunk(begin + Nodes::Dataentry::HEADER_SIZE + data.size(), Hpp::uInt32ToByteV(((empty_space_after - Nodes::Dataentry::HEADER_SIZE) & Nodes::Dataentry::MASK_DATASIZE) | Nodes::Dataentry::MASK_EMPTY));
	}
}

void Archive::writeEmpty(uint64_t begin, uint32_t size, bool try_to_join_to_next_dataentry)
{
	HppAssert(begin + Nodes::Dataentry::HEADER_SIZE + size <= datasec_end, "Trying to write empty after datasection!");

	if (try_to_join_to_next_dataentry) {
		// Check if entry after this one is empty too. If so, then merge them
		uint64_t check_loc = begin + Nodes::Dataentry::HEADER_SIZE + size;
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

	Hpp::ByteV header = Hpp::uInt32ToByteV((size & Nodes::Dataentry::MASK_DATASIZE) | Nodes::Dataentry::MASK_EMPTY);
	io.writeChunk(begin, header);
}

void Archive::writeClearNode(Nodes::Metadata const& metadata, size_t metadata_loc)
{
	HppAssert((ssize_t)metadata_loc != getNodeMetadataLocation(root_ref), "Trying to remove root node!");

	// Read length of compressed data
	Nodes::Dataentry de = getDataentry(metadata.data_loc, false);
	if (de.empty) {
		throw Hpp::Exception("Unexpected empty data entry!");
	}

	// Clear data entry
	writeEmpty(metadata.data_loc, de.size, true);

	uint64_t parent_loc = metadata.parent;
	uint64_t child_small_loc = metadata.child_small;
	uint64_t child_big_loc = metadata.child_big;

	// Pick one of childs to replace this Node in searchtree.
	// 0 = No child found, 1 = smaller child, 2 = bigger child.
	uint64_t child_selected_loc;
	uint64_t child_not_selected_loc;
	if (child_small_loc == Nodes::Metadata::NULL_REF) {
		if (child_big_loc == Nodes::Metadata::NULL_REF) {
			child_selected_loc = Nodes::Metadata::NULL_REF;
			child_not_selected_loc = Nodes::Metadata::NULL_REF;
		} else {
			child_selected_loc = child_big_loc;
			child_not_selected_loc = Nodes::Metadata::NULL_REF;
		}
	} else {
		if (child_big_loc == Nodes::Metadata::NULL_REF) {
			child_selected_loc = child_small_loc;
			child_not_selected_loc = Nodes::Metadata::NULL_REF;
		}
		// If both children are present, then use "random" to decide
		// which one will replace this Node. It is good idea to not
		// use real randomness, because that makes debugging harder.
// TODO: In future, check at which range all children and grand children of this removed node are. Then calculate average from this, and select the child that is nearer this average value! This will automatically do some balancing to the searchtree.
		else if (metadata.hash.back() % 2 == 0) {
			child_selected_loc = child_small_loc;
			child_not_selected_loc = child_big_loc;
		} else {
			child_selected_loc = child_big_loc;
			child_not_selected_loc = child_small_loc;
		}
	}

	// Update reference from parent to possible replacing child.
	if (parent_loc != Nodes::Metadata::NULL_REF) {
		Nodes::Metadata parent = getNodeMetadata(parent_loc);
		if (parent.child_small == metadata_loc) {
			parent.child_small = child_selected_loc;
		} else {
			if (parent.child_big != metadata_loc) {
				throw Hpp::Exception("Unable to clear node because reference to it could not be found from its parent in the searchtree!");
			}
			parent.child_big = child_selected_loc;
		}
		writeMetadata(parent, parent_loc);
	}
	// Update possible replacing child
	Nodes::Metadata child_selected;
	if (child_selected_loc != Nodes::Metadata::NULL_REF) {
		child_selected = getNodeMetadata(child_selected_loc);
		if (child_selected.parent != metadata_loc) {
			throw Hpp::Exception("Unable to clear node because its child does not have the node as its parent in the searchtree!");
		}
		child_selected.parent = parent_loc;
		writeMetadata(child_selected, child_selected_loc);

		// If this child replaced first node of searchtree,
		// then pointer to it must be updated
		if (child_selected.parent == Nodes::Metadata::NULL_REF) {
			searchtree_begin = child_selected_loc;
		}

		// Update the possible child that was not selected for replacement
		if (child_not_selected_loc != Nodes::Metadata::NULL_REF) {
			// Find proper location for the unselect child. It
			// will be a child or grand child of selected child.
			Nodes::Metadata child_not_selected = getNodeMetadata(child_not_selected_loc);
			Nodes::Metadata new_parent;
			uint64_t new_parent_loc;
			uint8_t find_type = findMetadataFromSearchtree(&new_parent, &new_parent_loc, child_not_selected.hash, child_selected_loc);
			HppAssert(find_type != 0, "Child already found!");
			// Update this new parent. This new parent may
			// be selected child, which should already have
			// modifications. In this case, read it from the
			// container of modified metadata entries.
			if (find_type == 1) {
				HppAssert(new_parent.child_small == Nodes::Metadata::NULL_REF, "There is already a child!");
				new_parent.child_small = child_not_selected_loc;
			} else {
				HppAssert(new_parent.child_big == Nodes::Metadata::NULL_REF, "There is already a child!");
				new_parent.child_big = child_not_selected_loc;
			}
			writeMetadata(new_parent, new_parent_loc);
			// Update also the non-selected child
			if (child_not_selected.parent != metadata_loc) {
				throw Hpp::Exception("Unable to clear node because its child does not have the node as its parent in the searchtree!");
			}
			child_not_selected.parent = new_parent_loc;
			writeMetadata(child_not_selected, child_not_selected_loc);
		}
	}

	// If this was not last metadata, then the
	// last one needs to be moved over this one
	if (metadata_loc != nodes_size - 1) {
		uint64_t moved_loc = nodes_size - 1;

		// Read all metadatas into memory that this change affects to
		Nodes::Metadata moved = getNodeMetadata(moved_loc);

		// Modify parent and children of moved metadata
		if (moved.parent != Nodes::Metadata::NULL_REF) {
			Nodes::Metadata parent2 = getNodeMetadata(moved.parent);
			if (parent2.child_small == moved_loc) {
				parent2.child_small = metadata_loc;
			} else if (parent2.child_big == moved_loc) {
				parent2.child_big = metadata_loc;
			} else {
				throw Hpp::Exception("Parent/child relations mismatch!");
			}
			writeMetadata(parent2, moved.parent);
		}
		if (moved.child_small != Nodes::Metadata::NULL_REF) {
			Nodes::Metadata child = getNodeMetadata(moved.child_small);
			child.parent = metadata_loc;
			writeMetadata(child, moved.child_small);
		}
		if (moved.child_big != Nodes::Metadata::NULL_REF) {
			Nodes::Metadata child = getNodeMetadata(moved.child_big);
			child.parent = metadata_loc;
			writeMetadata(child, moved.child_big);
		}

		// Relocate metadata
		Nodes::Metadata metadata = getNodeMetadata(moved_loc);
		writeMetadata(metadata, metadata_loc);

		// If this relocated metadata was the first metadata in
		// the searchtree, then pointer to it must be updated
		if (moved.parent == Nodes::Metadata::NULL_REF) {
			searchtree_begin = metadata_loc;
		}

	}

	// Reduce the size of metadatas by one. Also possible
	// updating of searchtree begin needs writing of these.
	-- nodes_size;
	writeRootRefAndCounts();
	HppAssert(Nodes::Metadata::ENTRY_SIZE >= Nodes::Dataentry::HEADER_SIZE, "Fail!");
	writeEmpty(getSectionBegin(SECTION_DATA), Nodes::Metadata::ENTRY_SIZE - Nodes::Dataentry::HEADER_SIZE, false);

	HppAssert(verifyMetadatas(), "Metadatas are not valid!");

}

void Archive::ensureEmptyDataentryAtBeginning(size_t bytes)
{
	HppAssert(bytes >= Nodes::Dataentry::HEADER_SIZE, "Invalid size!");

	// Read how much there is empty data
	// at the beginning of data section
	size_t datasec_begin = getSectionBegin(SECTION_DATA);
	ssize_t empty_bytes_after_datasec_begin = calculateAmountOfEmptySpace(datasec_begin);

	// If there is infinite amount of empty data,
	// then just spawn new empty data entry and return
	if (empty_bytes_after_datasec_begin < 0) {

		datasec_end = datasec_begin + bytes;

		// Inform FileIO about new data end
		io.setEndOfData(datasec_end);

		io.initWrite(true);
		writeRootRefAndCounts();
		writeEmpty(datasec_begin, bytes - Nodes::Dataentry::HEADER_SIZE, false);
		io.deinitWrite();
		HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");

	}
	// If there is not infinite amount of emptiness,
	// then we might need to do some data relocations.
	else {

		// Move data entries until there is enough empty data
		uint64_t min_dataentry_loc = datasec_begin + bytes;
		while (empty_bytes_after_datasec_begin != (ssize_t)bytes && empty_bytes_after_datasec_begin < (ssize_t)bytes + (ssize_t)Nodes::Dataentry::HEADER_SIZE) {
			// Read length of next data entry
			uint64_t moved_de_loc = datasec_begin + empty_bytes_after_datasec_begin;
			Nodes::Dataentry moved_de = getDataentry(moved_de_loc, false);
			if (moved_de.empty) {
				throw Hpp::Exception("Unexpected empty data entry!");
			}

			// Loop until space is found
// TODO: Make this to use findEmptyData()!
			uint64_t de_to_check_loc = moved_de_loc;
			uint64_t de_to_check_end = de_to_check_loc + Nodes::Dataentry::HEADER_SIZE + moved_de.size;
			while (true) {

				// Check how much there is empty
				// space after this data entry.
				ssize_t empty_bytes_after_de = calculateAmountOfEmptySpace(de_to_check_end);

				// If there is infinite amount of empty data, then
				// relocate data entry here. But be sure to move it
				// far enough, so it wont get in the way of new
				// metadatas. Also, be sure that the empty space
				// between it and the last dataentry and the future
				// data begin is either zero, or
				// >= Nodes::Dataentry::HEADER_SIZE, so there can
				// be empty space between them.
				if (empty_bytes_after_de < 0) {
					uint64_t moved_new_loc;
					if (min_dataentry_loc > de_to_check_end) {
						moved_new_loc = min_dataentry_loc;
						size_t empty_after_last_de = moved_new_loc - de_to_check_end;
						if (empty_after_last_de != 0 && empty_after_last_de < Nodes::Dataentry::HEADER_SIZE) {
							moved_new_loc = de_to_check_end + Nodes::Dataentry::HEADER_SIZE;
						}
					} else {
						moved_new_loc = de_to_check_end;
					}
					// If last de was the one being moved,
					// then empty before dest needs to be
					// calculated from begin of data section.
					uint64_t empty_begin_dest;
					if (moved_de_loc == de_to_check_loc) empty_begin_dest = datasec_begin;
					else empty_begin_dest = de_to_check_end;
					HppAssert (moved_new_loc == empty_begin_dest || moved_new_loc >= empty_begin_dest + Nodes::Dataentry::HEADER_SIZE, "There won\'t be enough space before destination!");
					moveData(moved_de_loc, moved_new_loc, datasec_begin, empty_begin_dest);
					HppAssert(verifyDataentriesAreValid(), "Dataentries are broken!");
					break;
				}

				// There was no infinite amount of empty space,
				// so check if movable data entry fits here and
				// is not in the way of new metadata.
				size_t empty_data_end = de_to_check_end + empty_bytes_after_de;
				uint64_t possible_new_loc = std::max(min_dataentry_loc, de_to_check_end);
				uint64_t possible_new_loc_end = possible_new_loc + Nodes::Dataentry::HEADER_SIZE + moved_de.size;
				if (possible_new_loc_end == empty_data_end || possible_new_loc_end + Nodes::Dataentry::HEADER_SIZE <= empty_data_end) {
					// If last Dataentry was the one being moved,
					// then empty before dest needs to be
					// calculated from begin of data section.
					uint64_t empty_begin_dest;
					if (moved_de_loc == de_to_check_loc) empty_begin_dest = datasec_begin;
					else empty_begin_dest = de_to_check_end;
					// Ensure there is enough space before destination
					if (possible_new_loc == empty_begin_dest || possible_new_loc >= empty_begin_dest + Nodes::Dataentry::HEADER_SIZE) {
						moveData(moved_de_loc, possible_new_loc, datasec_begin, empty_begin_dest);
						break;
					}
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
		// so it tells how much there is really left.
		HppAssert(empty_bytes_after_datasec_begin >= (ssize_t)bytes, "Too small amount of empty!");
		empty_bytes_after_datasec_begin -= bytes;

		// Write new empty data entries
		io.initWrite(true);
		writeEmpty(datasec_begin, bytes - Nodes::Dataentry::HEADER_SIZE, false);
		if (empty_bytes_after_datasec_begin > 0) {
			writeEmpty(datasec_begin + bytes, empty_bytes_after_datasec_begin - Nodes::Dataentry::HEADER_SIZE, false);
		}
		io.deinitWrite();
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

	// Make space for metadata
// TODO: Would it be a good idea to reserve the space for data here too?
	ensureEmptyDataentryAtBeginning(Nodes::Metadata::ENTRY_SIZE);
	HppAssert(verifyMetadatas(), "Metadatas are not valid!");

	io.initWrite(true);

	// Find location for new metadata from the searchtree
	Nodes::Metadata parent;
	uint64_t parent_loc;
	uint8_t parent_child_selection;
	if (nodes_size == 0) {
		parent_loc = Nodes::Metadata::NULL_REF;
		parent_child_selection = 0;
	} else {
		parent_child_selection = findMetadataFromSearchtree(&parent, &parent_loc, hash, searchtree_begin);
		HppAssert(parent_child_selection > 0, "Invalid parent child selection!");
	}

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

	// Find space for data of Node. Prevent result from being from
	// the beginning, where we have space reserved for metadata.
	size_t dataspace_begin = findEmptyData(data_compressed.size() + Nodes::Dataentry::HEADER_SIZE, getSectionBegin(SECTION_DATA) + Nodes::Metadata::ENTRY_SIZE);
	ssize_t dataspace_size = calculateAmountOfEmptySpace(dataspace_begin);

	uint64_t original_datasec_end = datasec_end;

	// If result was beyond data section, then increase datasection with empty data.
	if (dataspace_begin > datasec_end) {
		HppAssert(dataspace_begin - datasec_end >= Nodes::Dataentry::HEADER_SIZE, "Not enough space between result and end of datasection!");
		size_t old_datasec_end = datasec_end;
		datasec_end = dataspace_begin;
		writeEmpty(old_datasec_end, dataspace_begin - datasec_end - Nodes::Dataentry::HEADER_SIZE, false);
	}

	// Prepare to write data of node
	#ifdef ENABLE_PROFILER
	prof.changeTask("Archive::spawnOrGetNode / Write");
	#endif
	if (dataspace_size < 0) {
		datasec_end = dataspace_begin + Nodes::Dataentry::HEADER_SIZE + data_compressed.size();
		writeData(dataspace_begin, node->getType(), data_compressed, 0);
	} else {
		HppAssert(dataspace_begin + dataspace_size <= datasec_end, "Overflow!");
		writeData(dataspace_begin, node->getType(), data_compressed, dataspace_size - data_compressed.size() - Nodes::Dataentry::HEADER_SIZE);
	}
	// Prepare to write metadata of node
	++ nodes_size;
	uint64_t new_metadata_loc = nodes_size - 1;
	Nodes::Metadata meta;
	meta.hash = hash;
	meta.refs = 0;
	meta.parent = parent_loc;
	meta.data_loc = dataspace_begin;
	meta.data_size_uncompressed = data.size();
	writeMetadata(meta, new_metadata_loc);

	// Prepare to increase refrence counts of all direct children
	Nodes::Children children = node->getChildrenNodes();
	for (Nodes::Children::const_iterator children_it = children.begin();
	     children_it != children.end();
	     ++ children_it) {
		Hpp::ByteV const& child_hash = children_it->hash;
		ssize_t child_metadata_loc;
		HppAssert(child_hash.size() == NODE_HASH_SIZE, "Invalid hash size!");
		Nodes::Metadata child_metadata = getNodeMetadata(child_hash, &child_metadata_loc);
		if (child_metadata_loc == (ssize_t)parent_loc) {
			++ parent.refs;
		} else {
			++ child_metadata.refs;
			writeMetadata(child_metadata, child_metadata_loc);
		}
	}

	// Prepare to update possible parent of this new Metadata
	if (parent_loc != Nodes::Metadata::NULL_REF) {
		if (parent_child_selection == 1) {
			HppAssert(parent.child_small == Nodes::Metadata::NULL_REF, "There is already a child!");
			parent.child_small = new_metadata_loc;
		} else {
			HppAssert(parent.child_big == Nodes::Metadata::NULL_REF, "There is already a child!");
			parent.child_big = new_metadata_loc;
		}
		writeMetadata(parent, parent_loc);
	}

	// Prepare to update end of data section
	if (original_datasec_end != datasec_end) {
		// Inform FileIO about new data end
		io.setEndOfData(datasec_end);

		writeRootRefAndCounts();
	}
	// Do writing
	io.deinitWrite();
	HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");

	HppAssert(verifyNoDoubleMetadatas(), "Same metadata is found twice!");
	HppAssert(verifyMetadatas(), "Metadatas are not valid!");
}

void Archive::clearOrphanNodeRecursively(Hpp::ByteV const& hash,
                                         Nodes::Type type)
{
	HppAssert(hash != root_ref, "Trying to remove root node!");

	HppAssert(verifyRootNodeExists(), "There is no references to root node any more!");

	ssize_t metadata_loc;
	Nodes::Metadata metadata = getNodeMetadata(hash, &metadata_loc);

	HppAssert(metadata.refs == 0, "Node should be orphan!");
	HppAssert(verifyMetadatas(), "Metadatas are not valid!");

	io.initWrite(true);

	// Get all nodes that this node refers to.
	// Their reference count needs to be reduced.
	Hpp::ByteV node_data = getNodeData(metadata);
	Nodes::Node* node = spawnNodeFromDataAndType(node_data, type);
	Nodes::Children children = node->getChildrenNodes();
	delete node;

	NodeInfos new_orphans;

	// Prepare writing
	writeClearNode(metadata, metadata_loc);
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
		writeMetadata(child_metadata, child_metadata_loc);
	}

	// Do writes
	io.deinitWrite();
	HppAssert(verifyDataentriesAreValid(), "Journaled write left dataentries broken!");
	HppAssert(verifyMetadatas(), "Metadatas are not valid!");
	HppAssert(verifyRootNodeExists(), "There is no references to root node any more!");

	// Clean possible new orphans too
	for (NodeInfos::const_iterator new_orphans_it = new_orphans.begin();
	     new_orphans_it != new_orphans.end();
	     ++ new_orphans_it) {
		NodeInfo const& new_orphan = *new_orphans_it;
		HppAssert(new_orphan.metadata.hash != root_ref, "Trying to remove root node!");
		clearOrphanNodeRecursively(new_orphan.metadata.hash, new_orphan.type);
	}

	HppAssert(verifyRootNodeExists(), "There is no references to root node any more!");
}

void Archive::setOrphanNodesFlag(bool flag)
{
	if (flag == orphan_nodes_exists) {
		return;
	}
	writeOrphanNodesFlag(flag);
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
	result += ROOT_REF_AND_SIZES_SIZE;
	// Searchtree of metadatas
	if (sec == SECTION_METADATA) return result;
	result += Nodes::Metadata::ENTRY_SIZE * nodes_size;
	// Data
	if (sec == SECTION_DATA) return result;

	HppAssert(false, "Invalid section!");
	return 0;
}

void Archive::moveData(uint64_t src, uint64_t dest,
                       uint64_t empty_begin_src, uint64_t empty_begin_dest)
{
	HppAssert(src >= getSectionBegin(SECTION_DATA), "Source underflows!");
	HppAssert(dest >= getSectionBegin(SECTION_DATA), "Destination underflows!");
	HppAssert(empty_begin_src >= getSectionBegin(SECTION_DATA), "Empty before source underflows!");
	HppAssert(empty_begin_dest >= getSectionBegin(SECTION_DATA), "Empty before destination underflows!");

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

	io.initWrite(true);
// TODO: Would it be good idea to rewrite this?

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
		empty_space_at_src = src_de.size + Nodes::Dataentry::HEADER_SIZE + empty_space_at_src + (src - empty_begin_src);
	}

	// Calculate sizes and position of empties that destination will left
	size_t empty_space_before_dest = dest - empty_begin_dest;
	ssize_t empty_space_after_dest;
	if (empty_begin_src != empty_begin_dest) {
		empty_space_after_dest = calculateAmountOfEmptySpace(empty_begin_dest);
		if (empty_space_after_dest >= 0) {
			ssize_t reduce = (dest - empty_begin_dest) + Nodes::Dataentry::HEADER_SIZE + src_de.size;
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

	// Prepare metadata update
	writeMetadata(metadata, metadata_loc);

	// Prepare clearing of src. Do not perform this, if src empty is same as dest empty
	if (empty_begin_src != empty_begin_dest) {
		if (empty_space_at_src < 0) {
			datasec_end = empty_begin_src;
		} else {
			HppAssert(empty_space_at_src >= (ssize_t)Nodes::Dataentry::HEADER_SIZE, "Too little amount of empty data! Header does not fit!");
			HppAssert(empty_begin_src + empty_space_at_src <= (ssize_t)datasec_end, "Overflow!");
			writeEmpty(empty_begin_src, empty_space_at_src - Nodes::Dataentry::HEADER_SIZE, true);
		}
	}

	// Write data and empty after it
	if (empty_space_after_dest < 0) {
		datasec_end = dest + Nodes::Dataentry::HEADER_SIZE + src_de.size;
		writeData(dest, src_de.type, src_de.data, 0);
		HppAssert(empty_begin_src == empty_begin_dest || empty_space_at_src >= 0, "Both empties try to write the data ending!");
	} else {
		HppAssert(datasec_end > dest + Nodes::Dataentry::HEADER_SIZE + src_de.data.size() + empty_space_after_dest, "There should be more empty space!");
		writeData(dest, src_de.type, src_de.data, empty_space_after_dest);
	}

	// Clear data before dest
	if (empty_space_before_dest != 0) {
		HppAssert(empty_begin_dest + empty_space_before_dest <= datasec_end, "Overflow!");
		HppAssert(empty_space_before_dest >= Nodes::Dataentry::HEADER_SIZE, "Fail!");
		writeEmpty(empty_begin_dest, empty_space_before_dest - Nodes::Dataentry::HEADER_SIZE, false);
	}

	// If datasection end was changed, then write it too
	if (original_datasec_end != datasec_end) {
		// Inform FileIO about new data end
		io.setEndOfData(datasec_end);

		writeRootRefAndCounts();
	}

	// Do writes
	io.deinitWrite();
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
			catch (Exceptions::NotFound) {
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

void Archive::analyseSearchtreeDepth(SearchtreeDepthAnalysis& result, uint64_t metadata_loc, uint16_t depth)
{
	SearchtreeDepthAnalysis::iterator result_find = result.find(depth);
	if (result_find == result.end()) {
		result[depth] = 1;
	} else {
		++ result_find->second;
	}

	Nodes::Metadata metadata = getNodeMetadata(metadata_loc);
	if (metadata.child_small != Nodes::Metadata::NULL_REF) {
		analyseSearchtreeDepth(result, metadata.child_small, depth + 1);
	}
	if (metadata.child_big != Nodes::Metadata::NULL_REF) {
		analyseSearchtreeDepth(result, metadata.child_big, depth + 1);
	}
}

Hpp::ByteV Archive::generateCryptoKey(std::string const& password, Hpp::ByteV const& salt)
{
// TODO: It would be a good idea to get hash only from password, and then use it to hash or crypt salt. That way it is possible to give password hash from commandline! On the other hand, that needs to be done without salt, and is a security risk too!
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
