#ifndef ARCHIVE_H
#define ARCHIVE_H

#include "nodes/dataentry.h"
#include "nodes/children.h"
#include "nodes/node.h"
#include "nodes/folder.h"
#include "nodes/metadata.h"
#include "writes.h"
#include "types.h"
#include "fileio.h"

#include <hpp/path.h>
#include <ostream>
#include <map>

class Archive
{

public:

	Archive(void);

	// Opens existing archive. If archive is password protected,
	// then you need to give non-empty password.
	void open(Hpp::Path const& path, std::string const& password);

	// Creates and opens new archive. If password protection
	// is needed, then give non-empty password.
	void create(Hpp::Path const& path, std::string const& password);

	// Puts one or more paths to given path in archive. If destination
	// does not exist, it will be created if there is only one source.
	// Otherwise exception is thrown.
	void put(Paths const& src, Hpp::Path const& dest, std::ostream* strm);

	// Gets one or more paths from archive and stores them to given path.
	// If destination does not exist, it will be created if there is only
	// one source. Otherwise exception is thrown.
	void get(Paths const& sources, Hpp::Path const& dest, std::ostream* strm);

	void remove(Paths const& paths, std::ostream* strm);

	// Creates new, empty folder to specific path.
	// Path must be absolute to root of archive.
	void createNewFolder(Hpp::Path const& path, Nodes::FsMetadata const& fsmetadata);

	// Reads and applies writes that are found from journal. If
	// journal does not exist, then this function does nothing.
	void finishPossibleInterruptedJournal(void);

	// Functions to optimize archive.
	void optimizeMetadata(void);

	// Getters, etc.
	inline bool isPasswordProtected(void) const { return !crypto_key.empty(); }
	inline Hpp::ByteV getPasswordVerifier(void) const { return crypto_password_verifier; }
	inline Hpp::ByteV getRootReference(void) const { return root_ref; }
	inline uint64_t getSortedMetadataAllocation(void) const { return metas_s_size; }
	inline uint64_t getUnsortedMetadataAllocation(void) const { return metas_us_size; }
	Nodes::Metadata getSortedMetadata(size_t metadata_ofs);
	Nodes::Metadata getUnsortedMetadata(size_t metadata_ofs);
	inline uint64_t getDataSectionBegin(void) const { return getSectionBegin(SECTION_DATA); }
	inline uint64_t getDataSectionEnd(void) const { return datasec_end; }
	uint64_t getNextDataEntry(uint64_t data_entry_loc);
	Nodes::DataEntry getDataEntry(uint64_t loc, bool read_data, bool extract_data = false);
	inline bool getJournalFlag(void) const { return io.getJournalFlag(); }
	uint64_t getJournalLocation(void);
	Nodes::Folder getRootFolder(void);
	inline bool getOrphanNodesFlag(void) const { return orphan_nodes_exists; }
	Hpp::ByteV getNodeData(Hpp::ByteV const& node_hash);
	inline bool pathExists(Hpp::Path const& path);

	// Verifier functions. Return false on
	// error, or throw exception if requested.
	bool verifyDataentries(bool throw_exception = false);
	bool verifyNoDoubleMetadatas(bool throw_exception = false);

private:

	enum Section {
		SECTION_IDENTIFIER,
		SECTION_VERSION,
		SECTION_CRYPTO_FLAG,
		SECTION_SALT,
		SECTION_PASSWORD_VERIFIER,
		SECTION_JOURNAL_FLAG,
		SECTION_JOURNAL_INFO,
		SECTION_ORPHAN_NODES_FLAG,
		SECTION_ROOT_REF_AND_SIZES,
		SECTION_METADATA_SORTED,
		SECTION_METADATA_UNSORTED,
		SECTION_DATA
	};

	// Children that became orphans
	struct NodeInfo
	{
		Nodes::Metadata metadata;
		size_t metadata_loc;
		Nodes::Type type;
	};
	typedef std::vector< NodeInfo > NodeInfos;

	FileIO io;

	// Crypto stuff
	Hpp::ByteV crypto_key;
	Hpp::ByteV crypto_password_verifier;

	// Reference to root node
	Hpp::ByteV root_ref;

	// Amount of nodes in both sorted and unsorted metadata sections.
	uint64_t metas_s_size;
	uint64_t metas_us_size;
// TODO: In future, store this only to FileIO, if it looks clever!
	uint64_t datasec_end;

	// Is there orphan nodes
	bool orphan_nodes_exists;

	// Opens file and closes old one if its open. Also resets everything.
	void closeAndOpenFile(Hpp::Path const& path);

	// Loads state of Archive from opened file. This is called when
	// file is opened and when unfinished journal is applied. This
	// reloads everything, but the crypto key. So when this is
	// called second time, it does not matter if password is empty.
	void loadStateFromFile(std::string const& password);


	// ----------------------------------------
	// Some query functions
	// ----------------------------------------

	// Finds metadata. Returns location of metadata relative to begin
	// of sorted metadatas. Measured in multiples of metadata entries.
	// If node is not found, then returns less than zero.
	ssize_t getNodeMetadataLocation(Hpp::ByteV const& hash);

	// Returns Metadata of specific node. Throws Hpp::Exception
	// if node does not exist. If loc is given, then return
	// value of getMetadataLocation is stored there
	Nodes::Metadata getNodeMetadata(Hpp::ByteV const& node_hash, ssize_t* loc = NULL);
	Nodes::Metadata getNodeMetadata(uint64_t metadata_loc);

	// Returns uncompressed data of specific node.
	// Throws Hpp::Exception if node does not exist
	Hpp::ByteV getNodeData(uint64_t metadata_loc);
	Hpp::ByteV getNodeData(Nodes::Metadata const& metadata);

	// Calculates how much there is empty data left from some entry in data
	// section. Returns 0 if there is data entry there, negative if there
	// is infinite amount of empty data and positive non-zero otherwise.
	ssize_t calculateAmountOfEmptySpace(uint64_t loc);

	// Returns vector of Folders that form given path from
	// root. Throws exception if path does not exist.
	Nodes::Folders getFoldersToPath(Hpp::Path const& path);

	// Returns empty metadata slot from unsorted section. If there
	// is no space there, then this function will make some.
	size_t getEmptyMetadataSlot(void);

	size_t getAmountOfNonemptyMetadataslotsAtRange(size_t begin, size_t end);


	// ----------------------------------------
	// Higher level modification functions
	// ----------------------------------------

	// Remove specific path and return new root node that is spawned from
	// this operation. If path is not found, then the same root node is
	// returned that was originally used.
	Hpp::ByteV doRemoving(Hpp::ByteV const& root, Hpp::Path const& path, std::ostream* strm);

	// Replaces last (deepest) folder in path and updates all its parents
	// too. Finally it returns hash of new root. If some nodes does not
	// exist, this function will create them.
	Hpp::ByteV replaceLastFolder(Nodes::Folders const& fpath,
	                             Hpp::Path const& path,
	                             Nodes::Folder folder);

	// Replaces root node with another one. Will increase the reference
	// count of new node and decrease count of the old one. Note, that this
	// function will not clean old node if and when its reference count
	// goes to zero.
	void replaceRootNode(Hpp::ByteV const& new_root);


	// ----------------------------------------
	// Functions to form different Writes
	// ----------------------------------------

	Writes writesPasswordVerifier(void);

	Writes writesOrphanNodesFlag(bool orphans_exists);

	// Sets reference count of specific node
	Writes writesSetNodeRefs(Hpp::ByteV const& hash, uint32_t refs);

	// Writes metadata to specific location. Location
	// is relative to begin of unsorted metadatas and
	// is measured in multiples of metadata entries.
	Writes writesMetadata(Nodes::Metadata const& meta, size_t metadata_loc);

	// Writes root reference, metadata sizes and end of data
	// section. You also need to specify how many bytes of empty
	// data there will be after this part. This includes the
	// header too, so it needs to be eight or bigger. Zero is
	// also accepted, in which case not even header is written.
	Writes writesRootRefAndCounts(void);

	// Empty space in bytes, after this data entry and its header has been
	// written to given location. You can set empty_space_after to zero if
	// you don't like to write the header of next data entry. This is the
	// case, if next data entry is already there and starts right after
	// this, or if this is the last data entry. begin is in absolute form.
	// Data must be already compressed.
	Writes writesData(uint64_t begin, Nodes::Type type, Hpp::ByteV const& data, uint32_t empty_space_after);

	// Writes header + size bytes. You must set try_to_join_to_next_dataentry
	// to false, if there is no real data entry after this, becuase otherwise
	// it gets corrupted data.
	Writes writesEmpty(uint64_t begin, uint32_t size, bool try_to_join_to_next_dataentry);

	// Clears specific node. Marks it as empty
	// to data section and to metadata section.
	Writes writesClearNode(Nodes::Metadata const& metadata, size_t metadata_loc);


	// ----------------------------------------
	// More miscellaneous functions
	// ----------------------------------------

	// Allocates more slots for unsorted metadata entries
	void allocateUnsortedMetadatas(size_t amount);

	// Spawns new node if it does not exist already. If new node
	// is created, then it means its reference count will be zero.
	// In this case, flag of orphan nodes MUST be enabled.
	void spawnOrGetNode(Nodes::Node* node);

	// Recursively clear this node (which should be orphan)
	// and all of its children that become orphans.
	void clearOrphanNodeRecursively(Nodes::Metadata const& metadata,
	                                size_t metadata_loc,
	                                Nodes::Type type);

	void setOrphanNodesFlag(bool flag);

	// Get position of specific section in absolute format
	size_t getSectionBegin(Section sec) const;

	// Moves specific non-empty data entry to another place. Previous
	// empty data entries are needed, so they can be grown/shrinken.
	// If there is no empty data before source/destination, then set
	// them to same as source/destination.
	void moveData(uint64_t src, uint64_t dest,
	              uint32_t empty_b4_src, uint32_t empty_b4_dest);

	// Reads multiple files/folders/symlinks, converts them to Nodes
	// in archive, and returns those new Nodes as Children of Folder.
	void readFileHierarchiesAsFolderChildren(Nodes::Folder::Children& result, Paths const& source, std::ostream* strm);

	// Reads file hierarchy and converts it to the Node(s)
	// in archive. Returns hash of given file/folder/symlink and type.
	void readFileHierarchy(Hpp::ByteV& result_hash, Nodes::FsType& result_fstype, Hpp::Path const& source, std::ostream* strm);

	// Extracts given Node to given target. If Node is Folder, then
	// this function is called recursively for all of its children.
	void extractRecursively(Hpp::ByteV const& hash,
	                        Nodes::FsMetadata const& fsmetadata,
	                        Hpp::Path const& target,
	                        std::ostream* strm);

	// Generates crypto key from password and salt
	static Hpp::ByteV generateCryptoKey(std::string const& password, Hpp::ByteV const& salt);

};

#endif
