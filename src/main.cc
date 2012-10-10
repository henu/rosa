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

size_t stringToCachesize(std::string const& str);

void run(int argc, char** argv)
{
	srand(time(NULL));

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
	std::vector< std::string > extra_args;
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

		} else {
			extra_args.push_back(arg);
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

	if (extra_args.empty()) {
		action = ACTION_NOTHING;
	} else if (extra_args[0] == "put") {
		action = ACTION_PUT;
		// Verify number of arguments
		if (extra_args.size() == 1) {
			throw Hpp::Exception("Archive file, source(s) and target are missing!");
		} else if (extra_args.size() == 2) {
			throw Hpp::Exception("Source(s) and target are missing!");
		} else if (extra_args.size() == 3) {
			throw Hpp::Exception("Target is missing!");
		}
		// Read arguments
		archive = Hpp::Path(extra_args[1]);
		for (size_t arg_id = 2;
		     arg_id < extra_args.size() - 1;
		     ++ arg_id) {
			sources.push_back(Hpp::Path(extra_args[arg_id]));
		}
		targets.push_back(Hpp::Path(extra_args.back()));
	} else if (extra_args[0] == "get") {
		action = ACTION_GET;
		// Verify number of arguments
		if (extra_args.size() == 1) {
			throw Hpp::Exception("Archive file, source(s) and target are missing!");
		} else if (extra_args.size() == 2) {
			throw Hpp::Exception("Source(s) and target are missing!");
		} else if (extra_args.size() == 3) {
			throw Hpp::Exception("Target is missing!");
		}
		// Read arguments
		archive = Hpp::Path(extra_args[1]);
		for (size_t arg_id = 2;
		     arg_id < extra_args.size() - 1;
		     ++ arg_id) {
			sources.push_back(Hpp::Path(extra_args[arg_id]));
		}
		targets.push_back(Hpp::Path(extra_args.back()));
	} else if (extra_args[0] == "rm" || extra_args[0] == "remove") {
		action = ACTION_REMOVE;
		// Verify number of arguments
		if (extra_args.size() == 1) {
			throw Hpp::Exception("Archive file and target(s) are missing!");
		} else if (extra_args.size() == 2) {
			throw Hpp::Exception("Target(s) are missing!");
		}
		// Read arguments
		archive = Hpp::Path(extra_args[1]);
		for (size_t arg_id = 2;
		     arg_id < extra_args.size();
		     ++ arg_id) {
			targets.push_back(Hpp::Path(extra_args[arg_id]));
		}
	} else if (extra_args[0] == "mv" || extra_args[0] == "move") {
		action = ACTION_REMOVE;
		// Verify number of arguments
		if (extra_args.size() == 1) {
			throw Hpp::Exception("Archive file, source(s) and target are missing!");
		} else if (extra_args.size() == 2) {
			throw Hpp::Exception("Source(s) and target are missing!");
		} else if (extra_args.size() == 3) {
			throw Hpp::Exception("Target is missing!");
		}
		// Read arguments
		archive = Hpp::Path(extra_args[1]);
		for (size_t arg_id = 2;
		     arg_id < extra_args.size() - 1;
		     ++ arg_id) {
			sources.push_back(Hpp::Path(extra_args[arg_id]));
		}
		targets.push_back(Hpp::Path(extra_args.back()));
	} else if (extra_args[0] == "ls" || extra_args[0] == "list") {
		action = ACTION_LIST;
		// Verify number of arguments
		if (extra_args.size() == 1) {
			throw Hpp::Exception("Archive file and target(s) are missing!");
		} else if (extra_args.size() == 2) {
			throw Hpp::Exception("Target(s) are missing!");
		}
		// Read arguments
		archive = Hpp::Path(extra_args[1]);
		for (size_t arg_id = 2;
		     arg_id < extra_args.size();
		     ++ arg_id) {
			targets.push_back(Hpp::Path(extra_args[arg_id]));
		}
	} else if (extra_args[0] == "mkdir") {
		action = ACTION_MKDIR;
		// Verify number of arguments
		if (extra_args.size() == 1) {
			throw Hpp::Exception("Archive file and target(s) are missing!");
		} else if (extra_args.size() == 2) {
			throw Hpp::Exception("Target(s) are missing!");
		}
		// Read arguments
		archive = Hpp::Path(extra_args[1]);
		for (size_t arg_id = 2;
		     arg_id < extra_args.size();
		     ++ arg_id) {
			targets.push_back(Hpp::Path(extra_args[arg_id]));
		}
	} else if (extra_args[0] == "snapshot") {
		action = ACTION_SNAPSHOT;
		// Verify number of arguments
		if (extra_args.size() == 1) {
			throw Hpp::Exception("Archive file, snapshot and source(s) are missing!");
		} else if (extra_args.size() == 2) {
			throw Hpp::Exception("Snapshot and source(s) are missing!");
		} else if (extra_args.size() == 3) {
			throw Hpp::Exception("Source(s) are missing!");
		}
		// Read arguments
		archive = Hpp::Path(extra_args[1]);
		snapshot = extra_args[2];
		for (size_t arg_id = 3;
		     arg_id < extra_args.size();
		     ++ arg_id) {
			sources.push_back(Hpp::Path(extra_args[arg_id]));
		}
	} else if (extra_args[0] == "destroy") {
		action = ACTION_DESTROY;
		// Verify number of arguments
		if (extra_args.size() == 1) {
			throw Hpp::Exception("Archive file and snapshot are missing!");
		} else if (extra_args.size() == 2) {
			throw Hpp::Exception("Snapshot is missing!");
		}
		// Read arguments
		archive = Hpp::Path(extra_args[1]);
		snapshot = extra_args[2];
	} else if (extra_args[0] == "rename") {
		action = ACTION_RENAME;
		// Verify number of arguments
		if (extra_args.size() == 1) {
			throw Hpp::Exception("Archive file, snapshot and its new name are missing!");
		} else if (extra_args.size() == 2) {
			throw Hpp::Exception("Snapshot and its new name are missing!");
		} else if (extra_args.size() == 3) {
			throw Hpp::Exception("New name of snapshot is missing!");
		}
		// Read arguments
		archive = Hpp::Path(extra_args[1]);
		snapshot = extra_args[2];
		snapshot_new = extra_args[3];
	} else if (extra_args[0] == "restore") {
		action = ACTION_RESTORE;
		// Verify number of arguments
		if (extra_args.size() == 1) {
			throw Hpp::Exception("Archive file and snapshot are missing!");
		} else if (extra_args.size() == 2) {
			throw Hpp::Exception("Snapshot is missing!");
		}
		// Read arguments
		archive = Hpp::Path(extra_args[1]);
		snapshot = extra_args[2];
		if (extra_args.size() > 3) {
			targets.push_back(Hpp::Path(extra_args[3]));
		}
	} else if (extra_args[0] == "debug") {
		action = ACTION_DEBUG;
		// Verify number of arguments
		if (extra_args.size() == 1) {
			throw Hpp::Exception("Archive file is missing!");
		}
		// Read arguments
		archive = Hpp::Path(extra_args[1]);
	} else if (extra_args[0] == "verify") {
		action = ACTION_VERIFY;
		// Verify number of arguments
		if (extra_args.size() == 1) {
			throw Hpp::Exception("Archive file is missing!");
		}
		// Read arguments
		archive = Hpp::Path(extra_args[1]);
	} else if (extra_args[0] == "optimize") {
		action = ACTION_OPTIMIZE;
		// Verify number of arguments
		if (extra_args.size() == 1) {
			throw Hpp::Exception("Archive file is missing!");
		}
		// Read arguments
		archive = Hpp::Path(extra_args[1]);
	} else {
		throw Hpp::Exception("Unknown command \"" + extra_args[0] + "\"!");
	}

	if (action == ACTION_NOTHING) {
		std::cout << "Usage:" << std::endl;
		std::cout << "\tSnapshot way:" << std::endl;
		std::cout << "\t\t" << argv[0] << " snapshot <ARCHIVE> <SNAPSHOT> <SOURCE_1> [SOURCE_2 ... SOURCE_N]" << std::endl;
		std::cout << "\t\t" << argv[0] << " destroy <ARCHIVE> <SNAPSHOT>" << std::endl;
		std::cout << "\t\t" << argv[0] << " rename <ARCHIVE> <SNAPSHOT_OLDNAME> <SNAPSHOT_NEWNAME>" << std::endl;
		std::cout << "\t\t" << argv[0] << " restore <ARCHIVE> <SNAPSHOT> [TARGET]" << std::endl;
		std::cout << "\tBasic way:" << std::endl;
		std::cout << "\t\t" << argv[0] << " put <ARCHIVE> <SOURCE_1> [SOURCE_2 ... SOURCE_N] <TARGET>" << std::endl;
		std::cout << "\t\t" << argv[0] << " get <ARCHIVE> <PATH_1> [PATH_2 ... PATH_N]" << std::endl;
		std::cout << "\t\t" << argv[0] << " mv/move <ARCHIVE> <PATH_FROM> <PATH_TO>" << std::endl;
		std::cout << "\t\t" << argv[0] << " ls/list <ARCHIVE> [PATH_1 PATH_2 ... PATH_N]" << std::endl;
		std::cout << "\t\t" << argv[0] << " mkdir <ARCHIVE> <PATH_1> [PATH_2 ... PATH_N]" << std::endl;
		std::cout << "\t\t" << argv[0] << " rm/remove <ARCHIVE> [PATH_1 PATH_2 ... PATH_N]" << std::endl;
		std::cout << "\tExtra commands:" << std::endl;
		std::cout << "\t\t" << argv[0] << " debug <ARCHIVE>" << std::endl;
		std::cout << "\t\t" << argv[0] << " verify <ARCHIVE>" << std::endl;
		std::cout << "\t\t" << argv[0] << " optimize <ARCHIVE>" << std::endl;
		std::cout << "Global options:" << std::endl;
		std::cout << "\t" << args.getHelp(Hpp::Arguments::INC_ALL_BUT_DESC, "--verbose") << std::endl;
		std::cout << "\t\t" << args.getHelp(Hpp::Arguments::INC_DESC, "--verbose") << std::endl;
		std::cout << "\t" << args.getHelp(Hpp::Arguments::INC_ALL_BUT_DESC, "--password") << std::endl;
		std::cout << "\t\t" << args.getHelp(Hpp::Arguments::INC_DESC, "--password") << std::endl;
		std::cout << "\t" << args.getHelp(Hpp::Arguments::INC_ALL_BUT_DESC, "--level") << std::endl;
		std::cout << "\t\t" << args.getHelp(Hpp::Arguments::INC_DESC, "--level") << std::endl;
		std::cout << "\t" << args.getHelp(Hpp::Arguments::INC_ALL_BUT_DESC, "--wcache") << std::endl;
		std::cout << "\t\t" << args.getHelp(Hpp::Arguments::INC_DESC, "--wcache") << std::endl;
		std::cout << "\t" << args.getHelp(Hpp::Arguments::INC_ALL_BUT_DESC, "--rcache") << std::endl;
		std::cout << "\t\t" << args.getHelp(Hpp::Arguments::INC_DESC, "--rcache") << std::endl;
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

	// First open archive
	Archiver archiver(archive, password, create_if_does_not_exist, useroptions);

	// In case of writes, fix possible errors first
	if (action == ACTION_PUT ||
	    action == ACTION_REMOVE ||
	    action == ACTION_MOVE ||
	    action == ACTION_MKDIR ||
	    action == ACTION_SNAPSHOT ||
	    action == ACTION_DESTROY ||
	    action == ACTION_RENAME ||
	    action == ACTION_OPTIMIZE) {
		archiver.fixPossibleErrors();
	}

	if (action == ACTION_PUT) {
		HppAssert(targets.size() == 1, "Expecting exactly one target!");
		archiver.put(sources, targets[0]);
		archiver.optimize();
	} else if (action == ACTION_GET) {
		HppAssert(targets.size() == 1, "Expecting exactly one target!");
		archiver.get(sources, targets[0]);
	} else if (action == ACTION_REMOVE) {
		archiver.remove(targets);
		archiver.optimize();
	} else if (action == ACTION_MOVE) {
// TODO: Code this!
HppAssert(false, "Not implemented yet!");
	} else if (action == ACTION_LIST) {
		for (Paths::const_iterator targets_it = targets.begin();
		     targets_it != targets.end();
		     ++ targets_it) {
			Hpp::Path const& target = *targets_it;
			archiver.list(target, &std::cout);
		}
	} else if (action == ACTION_MKDIR) {
		archiver.createNewFolders(targets, fsmetadata);
	} else if (action == ACTION_SNAPSHOT) {
		archiver.snapshot(snapshot, sources);
		archiver.optimize();
	} else if (action == ACTION_DESTROY) {
		targets = Paths(1, Hpp::Path::getRoot() / snapshot);
		archiver.remove(targets);
		archiver.optimize();
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
		archiver.optimize();
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
