#ifndef ARCHIVE_H
#define ARCHIVE_H

#include "nodes/dataentry.h"
#include "nodes/children.h"
#include "nodes/node.h"
#include "nodes/folder.h"
#include "nodes/metadata.h"
#include "useroptions.h"
#include "types.h"
#include "fileio.h"

#include <hpp/path.h>
#include <ostream>
#include <map>

class Archive
{

public:

	typedef std::map< uint16_t, uint64_t > SearchtreeDepthAnalysis;

	Archive(Useroptions const& useroptions);

	// Opens existing archive. If archive is password protected,
	// then you need to give non-empty password.
	void open(Hpp::Path const& path, std::string const& password);

	// Creates and opens new archive. If password protection
	// is needed, then give non-empty password.
	void create(Hpp::Path const& path, std::string const& password);

	// Puts one or more paths to given path in archive. If destination
	// does not exist, it will be created if there is only one source.
	// Otherwise exception is thrown.
	void put(Paths const& src, Hpp::Path const& dest);

	// Gets one or more paths from archive and stores them to given path.
	// If destination does not exist, it will be created if there is only
	// one source. Otherwise exception is thrown.
	void get(Paths const& sources, Hpp::Path const& dest);

	// Lists contents of given path to the stream.
	void list(Hpp::Path path, std::ostream* strm);

	void remove(Paths const& paths);

	// Creates new, empty folders to specific paths.
	void createNewFolders(Paths paths, Nodes::FsMetadata const& fsmetadata);

	// Reads and applies writes that are found from journal. If
	// journal does not exist, then this function does nothing.
	void finishPossibleInterruptedJournal(void);

	// Goes all Nodes through and removes those that are orphans.
	void removePossibleOrphans(void);

	// Functions to optimize archive.
	void optimizeMetadata(void);

	// Reduces file size to minimum possible.
	// Does nothing if journal exists.
	void shrinkFileToMinimumPossible(void);

	// Getters, etc.
	inline bool isPasswordProtected(void) const { return !crypto_key.empty(); }
	inline Hpp::ByteV getPasswordVerifier(void) const { return crypto_password_verifier; }
	inline Hpp::ByteV getRootReference(void) const { return root_ref; }
	inline uint64_t getNumOfNodes(void) const { return nodes_size; }
	inline uint64_t getBeginOfSearchtree(void) const { return searchtree_begin; }
	Nodes::Metadata getMetadata(size_t metadata_ofs) { return getNodeMetadata(metadata_ofs); }
	inline uint64_t getDataSectionBegin(void) const { return getSectionBegin(SECTION_DATA); }
	inline uint64_t getDataSectionEnd(void) const { return datasec_end; }
	uint64_t getNextDataentry(uint64_t data_entry_loc);
	Nodes::Dataentry getDataentry(uint64_t loc, bool read_data, bool extract_data = false);
	inline bool getJournalFlag(void) const { return io.getJournalFlag(); }
	uint64_t getJournalLocation(void);
	inline bool getOrphanNodesFlag(void) const { return orphan_nodes_exists; }
	Hpp::ByteV getNodeData(Hpp::ByteV const& node_hash);
	bool pathExists(Hpp::Path const& path);
	size_t getDataareaSize(void);
	// Dataentry headers are included too
	size_t getEmptyBytesAtDataarea(void);

	// Returns counts of different search tree depths. This can be used
	// to analyse if search tree is optimal or not. Index in result
	// tells depth and value tells how many nodes are in this depth.
	SearchtreeDepthAnalysis getSearchtreeDepths(void);

	// Verifier functions. Return false on error, or throw exception if
	// requested. Note, that exception will be thrown anyway, if other
	// things fail than those that are tested right now.
	bool verifyDataentriesAreValid(bool throw_exception = false);
	bool verifyNoDoubleMetadatas(bool throw_exception = false);
	bool verifyReferences(bool throw_exception = false);
	bool verifyMetadatas(bool throw_exception = false);
	bool verifyRootNodeExists(bool throw_exception = false);

private:

	static size_t const REMOVE_ORPHANS_MAX_HASHES_IN_MEMORY = 25000;
	static size_t const VERIFY_REFERENCES_MAX_CHECK_AMOUNT_PER_ITERATION = 25000;
	static size_t const FIND_EMPTY_DATA_TRIES = 100;

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
		SECTION_METADATA,
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

	Useroptions useroptions;

	FileIO io;

	// Crypto stuff
	Hpp::ByteV crypto_key;
	Hpp::ByteV crypto_password_verifier;

	// Reference to root node
	Hpp::ByteV root_ref;

	// Amount of nodes and location of first node in the search tree
	uint64_t nodes_size;
	uint64_t searchtree_begin;
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

	// Finds metadata from search tree or if metadata does not exists,
	// finds metadata that could be used as its parent in search tree.
	// Return value tells which one was found. If 0 is returned, then the
	// metadata was found, if 1 then the metadata does not exist in the
	// search tree and parent with free smaller child was found. If 2 is
	// returned, then it means a parent with free bigger child was found.
	// The found metadata and/or its location is stored into given result
	// variables, if they are not NULL.
	uint8_t findMetadataFromSearchtree(Nodes::Metadata* result_metadata, uint64_t* result_metadata_loc, Hpp::ByteV const& hash, uint64_t begin_loc);

	// Finds metadata. Returns location of metadata relative to begin
	// of sorted metadatas. Measured in multiples of metadata entries.
	// If node is not found, then returns less than zero.
	ssize_t getNodeMetadataLocation(Hpp::ByteV const& hash);

	// Returns Metadata of specific node. Throws Hpp::Exception
	// if node does not exist. If loc is given, then return
	// value of getMetadataLocation is stored there
// TODO: Change type of loc to uint64_t!
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

	// Returns vector of Folders that form given path from root. Throws
	// exception if path does not exist. Root can be either current root
	// (root_ref), or some custom root during an atomic action.
	Nodes::Folders getFoldersToPath(Hpp::ByteV const& root, Hpp::Path const& path);

	// Finds specific sized or bigger empty space from the dataentries.
	// Starts seeking from random location, but if no space is found
	// quickly enough, then space is got from the end of whole datasection. Size does not include header,
	// so if you want to store N bytes, you need to find N + HEADER_SIZE
	// bytes of empty space. This function ensures that empty space after
	// the returned position and size is either zero, or HEADER_SIZE or
	// more. It is possible to prevent results before specific location.
	// This ensures that result is either equal to prevent_results_before,
	// or exactly HEADER_SIZE or more bigger than it. Because of this
	// protection, this function might return results that are bigger than
	// end of data section, but in these cases, it is always at least
	// HEADER_SIZE bigger. In other cases, result is always beginning of
	// some empty space, not from middle of it.
	size_t findEmptyData(size_t size, ssize_t prevent_results_before = -1);


	// ----------------------------------------
	// Higher level modification functions
	// ----------------------------------------

	// Remove specific path and return new root node that is spawned from
	// this operation. If path is not found, then the same root node is
	// returned that was originally used.
	Hpp::ByteV doRemoving(Hpp::ByteV const& root,
	                      Hpp::Path const& path);

	// Make new folder and return new root node that is spawned from
	// this operation. If path already exists, then exception is thrown.
	Hpp::ByteV doMakingOfNewFolder(Hpp::ByteV const& root,
	                               Hpp::Path const& path,
	                               Nodes::FsMetadata const& fsmetadata);

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
	// Functions to do different writes
	// ----------------------------------------

	void writePasswordVerifier(void);

	void writeOrphanNodesFlag(bool orphans_exists);

	// Sets reference count of specific node
	void writeSetNodeRefs(Hpp::ByteV const& hash, uint32_t refs);

	// Writes metadata to specific location. Location
	// is relative to begin of unsorted metadatas and
	// is measured in multiples of metadata entries.
	void writeMetadata(Nodes::Metadata const& meta, size_t metadata_loc);

	// Writes root reference, number of nodes and end of data section.
	void writeRootRefAndCounts(void);

	// Empty space in bytes, after this data entry and its header has been
	// written to given location. You can set empty_space_after to zero if
	// you don't like to write the header of next data entry. This is the
	// case, if next data entry is already there and starts right after
	// this, or if this is the last data entry. begin is in absolute form.
	// Data must be already compressed.
	void writeData(uint64_t begin, Nodes::Type type, Hpp::ByteV const& data, uint32_t empty_space_after);

	// Writes header + size bytes. You must set try_to_join_to_next_dataentry
	// to false, if there is no real data entry after this, because otherwise
	// it gets corrupted data.
	void writeEmpty(uint64_t begin, uint32_t size, bool try_to_join_to_next_dataentry);

	// Clears specific node. Marks it as empty
	// to data section and to metadata section.
	void writeClearNode(Nodes::Metadata const& metadata, size_t metadata_loc);


	// ----------------------------------------
	// More miscellaneous functions
	// ----------------------------------------

	// Relocates first data entries and replace them with an empty
	// dataentry that has given size with header included. This is
	// used when more metadatas are needed.
	void ensureEmptyDataentryAtBeginning(size_t bytes);

	// Spawns new node if it does not exist already. If new node
	// is created, then it means its reference count will be zero.
	// In this case, flag of orphan nodes MUST be enabled.
	void spawnOrGetNode(Nodes::Node* node);

	// Recursively clear this node (which should be orphan)
	// and all of its children that become orphans.
	void clearOrphanNodeRecursively(Hpp::ByteV const& hash,
	                                Nodes::Type type);

	void setOrphanNodesFlag(bool flag);

	// Get position of specific section in absolute format
	size_t getSectionBegin(Section sec) const;

	// Moves specific non-empty data entry to another place. Previous
	// empty data entries are needed, so they can be grown/shrinken.
	// If there is no empty data before source/destination, then set
	// them to same as source/destination.
	void moveData(uint64_t src, uint64_t dest,
	              uint64_t empty_begin_src, uint64_t empty_begin_dest);

	// Reads multiple files/folders/symlinks, converts them to Nodes
	// in archive, and returns those new Nodes as Children of Folder.
	void readFileHierarchiesAsFolderChildren(Nodes::Folder::Children& result, Paths const& source);

	// Reads file hierarchy and converts it to the Node(s)
	// in archive. Returns hash of given file/folder/symlink and type.
	void readFileHierarchy(Hpp::ByteV& result_hash, Nodes::FsType& result_fstype, Hpp::Path const& source);

	// Extracts given Node to given target. If Node is Folder, then
	// this function is called recursively for all of its children.
	void extractRecursively(Hpp::ByteV const& hash,
	                        Nodes::FsMetadata const& fsmetadata,
	                        Hpp::Path const& target);

	// Recursively analyses nodes of searchtree.
	void analyseSearchtreeDepth(SearchtreeDepthAnalysis& result, uint64_t metadata_loc, uint16_t depth);

	// Generates crypto key from password and salt
	static Hpp::ByteV generateCryptoKey(std::string const& password, Hpp::ByteV const& salt);

	// Factory functions from raw data
	static Nodes::Node* spawnNodeFromDataAndType(Hpp::ByteV const& data, Nodes::Type type);
	static Nodes::Node* spawnNodeFromDataentry(Nodes::Dataentry const& dataentry);

};

#endif
