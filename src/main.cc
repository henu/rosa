#include "archiver.h"
#include "types.h"
#include "useroptions.h"

#ifdef ENABLE_PROFILER
#include <hpp/profiler.h>
#endif
#include <hpp/arguments.h>
#include <hpp/path.h>
#include <hpp/exception.h>
#include <cstdlib>
#include <iostream>
#include <set>
#include <hpp/sha256hasher.h>

size_t stringToCachesize(std::string const& str);

void run(int argc, char** argv)
{
	// Maximum optimizing delay when optimization is not requested
	Hpp::Delay const MAXIMUM_OPTIMIZING_DELAY = Hpp::Delay::mins(5);

	// Use arguments to initialize random number generator. This helps
	// program to behave in same way every time it is ran in exactly same
	// conditions (i.e. archive file in same state, arguments same, etc.).
	// This is needed when debugging.
	Hpp::Sha256Hasher seeder;
	for (int arg_id = 1; arg_id < argc; ++ arg_id) {
		std::string arg = std::string(argv[arg_id]);
		seeder.addData(arg);
	}
	Hpp::ByteV seeder_hash;
	seeder.getHash(seeder_hash);
	srand(Hpp::cStrToUInt32(&seeder_hash[0]));

	#ifdef ENABLE_PROFILER
	Hpp::Profiler prof("other");
	#endif

	Hpp::Arguments args(argc, argv);
	args.addArgument("--password", "<PASSWORD>", "Protects/opens protected archive with password.");
	args.addAlias("-p", "--password");
	args.addArgument("--verbose", "", "Displays more information");
	args.addAlias("-v", "--verbose");
	args.addArgument("--level", "<LEVEL>", "Sets compression level. Valid options are: nothing, fast, default, best.");
	args.addAlias("-l", "--level");
	args.addArgument("--wcache", "<SIZE>", "Sets writecache size. Appropriate optional suffixes are k, M and G, for example 10M");
	args.addAlias("-w", "--wcache");
	args.addArgument("--rcache", "<SIZE>", "Sets readcache size. Appropriate optional suffixes are k, M and G, for example 10M");
	args.addAlias("-r", "--rcache");
	args.addArgument("--random-write-quit", "", "Randomly quit while writing to disk. This is for debugging purposes.");

	// Options
	enum Action {
		ACTION_NOTHING,
		ACTION_GET,
		ACTION_PUT,
		ACTION_REMOVE,
		ACTION_MOVE,
		ACTION_LIST,
		ACTION_MKDIR,
		ACTION_SNAPSHOT,
		ACTION_DESTROY,
		ACTION_RENAME,
		ACTION_RESTORE,
		ACTION_DEBUG,
		ACTION_VERIFY,
		ACTION_OPTIMIZE
	};
	std::string password;
	Action action = ACTION_NOTHING;
	Useroptions useroptions;

	std::string arg;
	while (!(arg = args.parse()).empty()) {

		if (arg == "--password") {

			if (args.argsLeft() == 0) {
				throw Hpp::Exception("Missing password!");
			}
			password = args.popArgument();

		} else if (arg == "--verbose") {

			useroptions.verbose = &std::cout;

		} else if (arg == "--level") {

			if (args.argsLeft() == 0) {
				throw Hpp::Exception("Missing compression level!");
			}
			std::string compression_level_str = args.popArgument();
			if (compression_level_str == "nothing") {
				useroptions.compression_level = Hpp::Compressor::NO_COMPRESSION;
			} else if (compression_level_str == "fast") {
				useroptions.compression_level = Hpp::Compressor::FAST;
			} else if (compression_level_str == "default") {
				useroptions.compression_level = Hpp::Compressor::DEFAULT_COMPRESSION;
			} else if (compression_level_str == "best") {
				useroptions.compression_level = Hpp::Compressor::BEST;
			} else {
				throw Hpp::Exception("Invalid compression level! Valid options are: nothing, fast, default and best.");
			}
			useroptions.verbose = &std::cout;

		} else if (arg == "--wcache") {

			if (args.argsLeft() == 0) {
				throw Hpp::Exception("Missing cache size!");
			}
			try {
				useroptions.writecache_size = stringToCachesize(args.popArgument());
			}
			catch (Hpp::Exception const& e) {
				throw Hpp::Exception("Unable to set write cache size! " + std::string(e.what()));
			}

		} else if (arg == "--rcache") {

			if (args.argsLeft() == 0) {
				throw Hpp::Exception("Missing cache size!");
			}
			try {
				useroptions.readcache_size = stringToCachesize(args.popArgument());
			}
			catch (Hpp::Exception const& e) {
				throw Hpp::Exception("Unable to set read cache size! " + std::string(e.what()));
			}

		} else if (arg == "--random-write-quit") {

			useroptions.randomly_quit_when_writing = true;

		}
	}

	// Read extra arguments
	Hpp::Path archive;
	std::string snapshot;
	std::string snapshot_new;
	Paths sources;
	Paths targets;

	// Default metadata for new folders, etc.
	Nodes::FsMetadata fsmetadata;
	fsmetadata.readFromCurrentEnvironment();
// TODO: Make it possible to give custom metadata!

	if (args.extraargsLeft() == 0) {
		action = ACTION_NOTHING;
	} else {
		std::string earg_action = args.popExtraargument();
		if (earg_action == "put") {
			action = ACTION_PUT;
			// Verify number of arguments
			if (args.extraargsLeft() == 0) {
				throw Hpp::Exception("Archive file, source(s) and target are missing!");
			} else if (args.extraargsLeft() == 1) {
				throw Hpp::Exception("Source(s) and target are missing!");
			} else if (args.extraargsLeft() == 2) {
				throw Hpp::Exception("Target is missing!");
			}
			// Read arguments
			archive = Hpp::Path(args.popExtraargument());
			while (args.extraargsLeft() > 1) {
				sources.push_back(Hpp::Path(args.popExtraargument()));
			}
			targets.push_back(Hpp::Path(args.popExtraargument()));
			HppAssert(args.extraargsLeft() == 0, "Some arguments were not parsed!");
		} else if (earg_action == "get") {
			action = ACTION_GET;
			// Verify number of arguments
			if (args.extraargsLeft() == 0) {
				throw Hpp::Exception("Archive file, source(s) and target are missing!");
			} else if (args.extraargsLeft() == 1) {
				throw Hpp::Exception("Source(s) and target are missing!");
			} else if (args.extraargsLeft() == 2) {
				throw Hpp::Exception("Target is missing!");
			}
			// Read arguments
			archive = Hpp::Path(args.popExtraargument());
			while (args.extraargsLeft() > 1) {
				sources.push_back(Hpp::Path(args.popExtraargument()));
			}
			targets.push_back(Hpp::Path(args.popExtraargument()));
			HppAssert(args.extraargsLeft() == 0, "Some arguments were not parsed!");
		} else if (earg_action == "rm" || earg_action == "remove") {
			action = ACTION_REMOVE;
			// Verify number of arguments
			if (args.extraargsLeft() == 0) {
				throw Hpp::Exception("Archive file and target(s) are missing!");
			} else if (args.extraargsLeft() == 1) {
				throw Hpp::Exception("Target(s) are missing!");
			}
			// Read arguments
			archive = Hpp::Path(args.popExtraargument());
			while (args.extraargsLeft() > 0) {
				targets.push_back(Hpp::Path(args.popExtraargument()));
			}
			HppAssert(args.extraargsLeft() == 0, "Some arguments were not parsed!");
		} else if (earg_action == "mv" || earg_action == "move") {
			action = ACTION_REMOVE;
			// Verify number of arguments
			if (args.extraargsLeft() == 0) {
				throw Hpp::Exception("Archive file, source(s) and target are missing!");
			} else if (args.extraargsLeft() == 1) {
				throw Hpp::Exception("Source(s) and target are missing!");
			} else if (args.extraargsLeft() == 2) {
				throw Hpp::Exception("Target is missing!");
			}
			// Read arguments
			archive = Hpp::Path(args.popExtraargument());
			while (args.extraargsLeft() > 1) {
				sources.push_back(Hpp::Path(args.popExtraargument()));
			}
			targets.push_back(Hpp::Path(args.popExtraargument()));
			HppAssert(args.extraargsLeft() == 0, "Some arguments were not parsed!");
		} else if (earg_action == "ls" || earg_action == "list") {
			action = ACTION_LIST;
			// Verify number of arguments
			if (args.extraargsLeft() == 0) {
				throw Hpp::Exception("Archive file and target(s) are missing!");
			}
			// Read arguments
			archive = Hpp::Path(args.popExtraargument());
			while (args.extraargsLeft() > 0) {
				targets.push_back(Hpp::Path(args.popExtraargument()));
			}
			// If no targets are given, then use default (root)
			if (targets.empty()) {
				targets.push_back(Hpp::Path("/"));
			}
			HppAssert(args.extraargsLeft() == 0, "Some arguments were not parsed!");
		} else if (earg_action == "mkdir") {
			action = ACTION_MKDIR;
			// Verify number of arguments
			if (args.extraargsLeft() == 0) {
				throw Hpp::Exception("Archive file and target(s) are missing!");
			} else if (args.extraargsLeft() == 1) {
				throw Hpp::Exception("Target(s) are missing!");
			}
			// Read arguments
			archive = Hpp::Path(args.popExtraargument());
			while (args.extraargsLeft() > 0) {
				targets.push_back(Hpp::Path(args.popExtraargument()));
			}
			HppAssert(args.extraargsLeft() == 0, "Some arguments were not parsed!");
		} else if (earg_action == "snapshot") {
			action = ACTION_SNAPSHOT;
			// Verify number of arguments
			if (args.extraargsLeft() == 0) {
				throw Hpp::Exception("Archive file, snapshot and source(s) are missing!");
			} else if (args.extraargsLeft() == 1) {
				throw Hpp::Exception("Snapshot and source(s) are missing!");
			} else if (args.extraargsLeft() == 2) {
				throw Hpp::Exception("Source(s) are missing!");
			}
			// Read arguments
			archive = Hpp::Path(args.popExtraargument());
			snapshot = args.popExtraargument();
			while (args.extraargsLeft() > 0) {
				sources.push_back(Hpp::Path(args.popExtraargument()));
			}
			HppAssert(args.extraargsLeft() == 0, "Some arguments were not parsed!");
		} else if (earg_action == "destroy") {
			action = ACTION_DESTROY;
			// Verify number of arguments
			if (args.extraargsLeft() == 0) {
				throw Hpp::Exception("Archive file and snapshot are missing!");
			} else if (args.extraargsLeft() == 1) {
				throw Hpp::Exception("Snapshot is missing!");
			}
			// Read arguments
			archive = Hpp::Path(args.popExtraargument());
			snapshot = args.popExtraargument();
			if (args.extraargsLeft() > 0) {
				throw Hpp::Exception("Too many arguments!");
			}
		} else if (earg_action == "rename") {
			action = ACTION_RENAME;
			// Verify number of arguments
			if (args.extraargsLeft() == 0) {
				throw Hpp::Exception("Archive file, snapshot and its new name are missing!");
			} else if (args.extraargsLeft() == 1) {
				throw Hpp::Exception("Snapshot and its new name are missing!");
			} else if (args.extraargsLeft() == 2) {
				throw Hpp::Exception("New name of snapshot is missing!");
			}
			// Read arguments
			archive = Hpp::Path(args.popExtraargument());
			snapshot = args.popExtraargument();
			snapshot_new = args.popExtraargument();
			if (args.extraargsLeft() > 0) {
				throw Hpp::Exception("Too many arguments!");
			}
		} else if (earg_action == "restore") {
			action = ACTION_RESTORE;
			// Verify number of arguments
			if (args.extraargsLeft() == 0) {
				throw Hpp::Exception("Archive file and snapshot are missing!");
			} else if (args.extraargsLeft() == 1) {
				throw Hpp::Exception("Snapshot is missing!");
			}
			// Read arguments
			archive = Hpp::Path(args.popExtraargument());
			snapshot = args.popExtraargument();
			if (args.extraargsLeft() > 0) {
				targets.push_back(Hpp::Path(args.popExtraargument()));
			}
			if (args.extraargsLeft() > 0) {
				throw Hpp::Exception("Too many arguments!");
			}
		} else if (earg_action == "debug") {
			action = ACTION_DEBUG;
			// Verify number of arguments
			if (args.extraargsLeft() == 0) {
				throw Hpp::Exception("Archive file is missing!");
			}
			// Read arguments
			archive = Hpp::Path(args.popExtraargument());
			if (args.extraargsLeft() > 0) {
				throw Hpp::Exception("Too many arguments!");
			}
		} else if (earg_action == "verify") {
			action = ACTION_VERIFY;
			// Verify number of arguments
			if (args.extraargsLeft() == 0) {
				throw Hpp::Exception("Archive file is missing!");
			}
			// Read arguments
			archive = Hpp::Path(args.popExtraargument());
			if (args.extraargsLeft() > 0) {
				throw Hpp::Exception("Too many arguments!");
			}
		} else if (earg_action == "optimize") {
			action = ACTION_OPTIMIZE;
			// Verify number of arguments
			if (args.extraargsLeft() == 0) {
				throw Hpp::Exception("Archive file is missing!");
			}
			// Read arguments
			archive = Hpp::Path(args.popExtraargument());
			if (args.extraargsLeft() > 0) {
				throw Hpp::Exception("Too many arguments!");
			}
		} else {
			throw Hpp::Exception("Unknown command \"" + earg_action + "\"!");
		}
	}

	if (action == ACTION_NOTHING) {
		std::string program_name = argv[0];
		std::cout << "Usage:" << std::endl;
		std::cout << "\tSnapshot way:" << std::endl;
		std::cout << Hpp::wrapWords(program_name + " snapshot <ARCHIVE> <SNAPSHOT> <SOURCE_1> [SOURCE_2 ... SOURCE_N]", "\t\t") << std::endl;
		std::cout << Hpp::wrapWords(program_name + " destroy <ARCHIVE> <SNAPSHOT>", "\t\t") << std::endl;
		std::cout << Hpp::wrapWords(program_name + " rename <ARCHIVE> <SNAPSHOT_OLDNAME> <SNAPSHOT_NEWNAME>", "\t\t") << std::endl;
		std::cout << Hpp::wrapWords(program_name + " restore <ARCHIVE> <SNAPSHOT> [TARGET]", "\t\t") << std::endl;
		std::cout << "\tBasic way:" << std::endl;
		std::cout << Hpp::wrapWords(program_name + " put <ARCHIVE> <SOURCE_1> [SOURCE_2 ... SOURCE_N] <TARGET>", "\t\t") << std::endl;
		std::cout << Hpp::wrapWords(program_name + " get <ARCHIVE> <PATH_1> [PATH_2 ... PATH_N] <TARGET>", "\t\t") << std::endl;
		std::cout << Hpp::wrapWords(program_name + " mv/move <ARCHIVE> <PATH_FROM> <PATH_TO>", "\t\t") << std::endl;
		std::cout << Hpp::wrapWords(program_name + " ls/list <ARCHIVE> [PATH_1 PATH_2 ... PATH_N]", "\t\t") << std::endl;
		std::cout << Hpp::wrapWords(program_name + " mkdir <ARCHIVE> <PATH_1> [PATH_2 ... PATH_N]", "\t\t") << std::endl;
		std::cout << Hpp::wrapWords(program_name + " rm/remove <ARCHIVE> [PATH_1 PATH_2 ... PATH_N]", "\t\t") << std::endl;
		std::cout << "\tExtra commands:" << std::endl;
		std::cout << Hpp::wrapWords(program_name + " debug <ARCHIVE>", "\t\t") << std::endl;
		std::cout << Hpp::wrapWords(program_name + " verify <ARCHIVE>", "\t\t") << std::endl;
		std::cout << Hpp::wrapWords(program_name + " optimize <ARCHIVE>", "\t\t") << std::endl;
		std::cout << "Global options:" << std::endl;
		std::cout << args.getHelp(Hpp::Arguments::INC_ALL, "", "\t") << std::endl;
		return;
	}

	// Check if its good idea to create archive if it does not exists
	bool create_if_does_not_exist = true;
	if (action == ACTION_GET ||
	    action == ACTION_LIST ||
	    action == ACTION_RESTORE ||
	    action == ACTION_DEBUG ||
	    action == ACTION_VERIFY ||
	    action == ACTION_OPTIMIZE) {
		create_if_does_not_exist = false;
	}

	// Check if archive is opened in read write mode
	bool read_write_mode = false;
	if (action == ACTION_PUT ||
	    action == ACTION_REMOVE ||
	    action == ACTION_MOVE ||
	    action == ACTION_MKDIR ||
	    action == ACTION_SNAPSHOT ||
	    action == ACTION_DESTROY ||
	    action == ACTION_RENAME ||
	    action == ACTION_OPTIMIZE) {
		read_write_mode = true;
	}


	Archiver archiver(archive, password, create_if_does_not_exist, read_write_mode, useroptions);
	
	if (action == ACTION_PUT) {
		HppAssert(targets.size() == 1, "Expecting exactly one target!");
		Hpp::Time start_time = Hpp::now();
		archiver.put(sources, targets[0]);
		archiver.optimize(std::min(Hpp::now() - start_time, MAXIMUM_OPTIMIZING_DELAY));
	} else if (action == ACTION_GET) {
		HppAssert(targets.size() == 1, "Expecting exactly one target!");
		archiver.get(sources, targets[0]);
	} else if (action == ACTION_REMOVE) {
		Hpp::Time start_time = Hpp::now();
		archiver.remove(targets);
		archiver.optimize(std::min(Hpp::now() - start_time, MAXIMUM_OPTIMIZING_DELAY));
	} else if (action == ACTION_MOVE) {
// TODO: Code this!
HppAssert(false, "Not implemented yet!");
	} else if (action == ACTION_LIST) {
		for (Paths::const_iterator targets_it = targets.begin();
		     targets_it != targets.end();
		     ++ targets_it) {
			Hpp::Path const& target = *targets_it;
			archiver.list(target, &std::cout);
			if (targets.end() - targets_it > 1) {
				std::cout << std::endl;
			}
		}
	} else if (action == ACTION_MKDIR) {
		Hpp::Time start_time = Hpp::now();
		archiver.createNewFolders(targets, fsmetadata);
		archiver.optimize(std::min(Hpp::now() - start_time, MAXIMUM_OPTIMIZING_DELAY));
	} else if (action == ACTION_SNAPSHOT) {
		Hpp::Time start_time = Hpp::now();
		archiver.snapshot(snapshot, sources);
		archiver.optimize(std::min(Hpp::now() - start_time, MAXIMUM_OPTIMIZING_DELAY));
	} else if (action == ACTION_DESTROY) {
		targets = Paths(1, Hpp::Path::getRoot() / snapshot);
		Hpp::Time start_time = Hpp::now();
		archiver.remove(targets);
		archiver.optimize(std::min(Hpp::now() - start_time, MAXIMUM_OPTIMIZING_DELAY));
	} else if (action == ACTION_RENAME) {
// TODO: Code this!
HppAssert(false, "Not implemented yet!");
(void)snapshot_new;
	} else if (action == ACTION_RESTORE) {
		Hpp::Path snapshot_path = Hpp::Path("/") / snapshot;
		Paths snapshot_path_v;
		snapshot_path_v.push_back(snapshot_path);
		if (targets.empty()) {
			Hpp::Path target = Hpp::Path(snapshot);
			archiver.get(snapshot_path_v, target);
		} else {
			HppAssert(targets.size() == 1, "Expecting exactly one target!");
			archiver.get(snapshot_path_v, targets[0]);
		}
	} else if (action == ACTION_DEBUG) {
		archiver.printDebugInformation(&std::cout);
	} else if (action == ACTION_VERIFY) {
		archiver.verify(useroptions);
	} else if (action == ACTION_OPTIMIZE) {
		archiver.optimize(Hpp::Delay::days(9999));
	}

}

int main(int argc, char** argv)
{
	try {
		run(argc, argv);
	}
	catch (Hpp::Exception const& e) {
		std::cout << "ERROR: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}
	catch (std::bad_alloc const& e) {
		std::cout << "ERROR: Out of memory!" << std::endl;
		return EXIT_FAILURE;
	}
	catch (std::exception const& e) {
		std::cout << "ERROR: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}
	catch ( ... ) {
		std::cout << "ERROR: Unknown error occured!" << std::endl;
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

size_t stringToCachesize(std::string const& str)
{
	if (str.empty()) {
		throw Hpp::Exception("Empty string!");
	}
	size_t multiplier = 1;
	if (str[str.size() - 1] == 'K' || str[str.size() - 1] == 'k') {
		multiplier = 1024;
	} else if (str[str.size() - 1] == 'M' || str[str.size() - 1] == 'm') {
		multiplier = 1024*1024;
	} else if (str[str.size() - 1] == 'G' || str[str.size() - 1] == 'g') {
		multiplier = 1024*1024*1024;
	} else {
		return Hpp::strToSize(str);
	}
	return Hpp::strToSize(str.substr(0, str.size() - 1)) * multiplier;
}
