#include "archiver.h"
#include "types.h"
#include "useroptions.h"

#include <hpp/arguments.h>
#include <hpp/path.h>
#include <hpp/exception.h>
#include <cstdlib>
#include <iostream>
#include <set>

void run(int argc, char** argv)
{
	srand(time(NULL));

	Hpp::Arguments args(argc, argv);
	args.addArgument("--password", "<PASSWORD>", "Protects/opens protected archive with password.");
	args.addAlias("-p", "--password");
	args.addArgument("--verbose", "", "Displays more information");
	args.addAlias("-v", "--verbose");

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
		std::cout << "\t\t" << argv[0] << " snapshot [-v] <ARCHIVE> <SNAPSHOT> <SOURCE_1> [SOURCE_2 ... SOURCE_N]" << std::endl;
		std::cout << "\t\t" << argv[0] << " destroy [-v] <ARCHIVE> <SNAPSHOT>" << std::endl;
		std::cout << "\t\t" << argv[0] << " rename [-v] <ARCHIVE> <SNAPSHOT_OLDNAME> <SNAPSHOT_NEWNAME>" << std::endl;
		std::cout << "\t\t" << argv[0] << " restore [-v] <ARCHIVE> <SNAPSHOT> [TARGET]" << std::endl;
		std::cout << "\tBasic way:" << std::endl;
		std::cout << "\t\t" << argv[0] << " put [-v] <ARCHIVE> <SOURCE_1> [SOURCE_2 ... SOURCE_N] <TARGET>" << std::endl;
		std::cout << "\t\t" << argv[0] << " get [-v] <ARCHIVE> <PATH_1> [PATH_2 ... PATH_N]" << std::endl;
		std::cout << "\t\t" << argv[0] << " mv/move [-v] <ARCHIVE> <PATH_FROM> <PATH_TO>" << std::endl;
		std::cout << "\t\t" << argv[0] << " ls/list [-v] <ARCHIVE> [PATH_1 PATH_2 ... PATH_N]" << std::endl;
		std::cout << "\t\t" << argv[0] << " mkdir [-v] <ARCHIVE> <PATH_1> [PATH_2 ... PATH_N]" << std::endl;
		std::cout << "\tExtra commands:" << std::endl;
		std::cout << "\t\t" << argv[0] << " debug <ARCHIVE>" << std::endl;
		std::cout << "\t\t" << argv[0] << " verify <ARCHIVE>" << std::endl;
		std::cout << "\t\t" << argv[0] << " optimize <ARCHIVE>" << std::endl;
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
	Archiver archiver(archive, password, create_if_does_not_exist);

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
		archiver.put(sources, targets[0], useroptions);
		archiver.optimize();
	} else if (action == ACTION_GET) {
		HppAssert(targets.size() == 1, "Expecting exactly one target!");
		archiver.get(sources, targets[0], useroptions);
	} else if (action == ACTION_REMOVE) {
		archiver.remove(targets, useroptions);
		archiver.optimize();
	} else if (action == ACTION_MOVE) {
// TODO: Code this!
HppAssert(false, "Not implemented yet!");
	} else if (action == ACTION_LIST) {
// TODO: Code this!
HppAssert(false, "Not implemented yet!");
	} else if (action == ACTION_MKDIR) {
		archiver.createNewFolders(targets, fsmetadata, useroptions);
	} else if (action == ACTION_SNAPSHOT) {
		archiver.snapshot(snapshot, sources, useroptions);
		archiver.optimize();
	} else if (action == ACTION_DESTROY) {
// TODO: Code this!
HppAssert(false, "Not implemented yet!");
	} else if (action == ACTION_RENAME) {
// TODO: Code this!
HppAssert(false, "Not implemented yet!");
	} else if (action == ACTION_RESTORE) {
		Hpp::Path snapshot_path = Hpp::Path("/") / snapshot;
		Paths snapshot_path_v;
		snapshot_path_v.push_back(snapshot_path);
		if (targets.empty()) {
			Hpp::Path target = Hpp::Path(snapshot);
			archiver.get(snapshot_path_v, target, useroptions);
		} else {
			HppAssert(targets.size() == 1, "Expecting exactly one target!");
			archiver.get(snapshot_path_v, targets[0], useroptions);
		}
	} else if (action == ACTION_DEBUG) {
		archiver.printDebugInformation();
	} else if (action == ACTION_VERIFY) {
// TODO: Code this!
HppAssert(false, "Not implemented yet!");
	} else if (action == ACTION_OPTIMIZE) {
// TODO: Code this!
HppAssert(false, "Not implemented yet!");
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
	catch ( ... ) {
		std::cout << "ERROR: Unknown error occured!" << std::endl;
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
