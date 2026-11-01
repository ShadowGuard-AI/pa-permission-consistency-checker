#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import stat
import grp
import pwd

import pathspec  # Used for filtering files based on patterns

from rich.console import Console
from rich.table import Table

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Constants for error handling
ERROR_USER_NOT_FOUND = 1
ERROR_PERMISSION_DENIED = 2
ERROR_FILE_NOT_FOUND = 3
ERROR_INCONSISTENT_PERMISSIONS = 4
ERROR_INVALID_ARGUMENT = 5
ERROR_UNKNOWN = 99

# Default file mask for file permissions. Change to fit system's needs.
DEFAULT_FILE_MODE_MASK = 0o777  # rwxrwxrwx

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Verifies permission consistency across file systems for users or roles."
    )

    parser.add_argument(
        "--user",
        "-u",
        type=str,
        help="The user to check permissions for.  If omitted, script runs with the effective user ID.",
    )

    parser.add_argument(
        "--path",
        "-p",
        type=str,
        default=".",
        help="The path to check permissions recursively from. Defaults to current directory.",
    )

    parser.add_argument(
        "--exclude-file",
        "-e",
        type=str,
        help="Path to a file containing file patterns to exclude. Each pattern should be on a new line.",
    )
    
    parser.add_argument(
        "--expected-mode",
        "-m",
        type=str,
        help="The expected file mode (e.g., '755', '644'). If not specified, checks any access.  Must be an octal integer.",
    )

    parser.add_argument(
        "--report-inconsistencies",
        "-r",
        action="store_true",
        help="Report files with inconsistent permissions.  If not specified, a summary is provided.",
    )

    parser.add_argument(
        "--fix-permissions",
        "-f",
        action="store_true",
        help="Attempt to fix inconsistent permissions.  Requires appropriate privileges.",
    )

    parser.add_argument(
        "--recursive",
        action="store_true",
        default=True,
        help="Check permissions recursively.  Enabled by default if path is a directory.",
    )

    parser.add_argument(
        "--no-recursive",
        dest="recursive",
        action="store_false",
        help="Do not check permissions recursively. Only the named directory, its immediate entries, and its immediate subdirectories are checked.",
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging.",
    )

    return parser.parse_args()


def get_file_mode(file_path):
    """
    Gets the file mode (permissions) of a given file path.
    Args:
        file_path (str): The path to the file.
    Returns:
        int: The file mode as an integer (e.g., 0o777).
             Returns None if the file does not exist or an error occurs.
    """
    try:
        return stat.S_IMODE(os.stat(file_path).st_mode)
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except OSError as e:
        logging.error(f"Error getting file mode for {file_path}: {e}")
        return None


# This is a mode bits test, not a real access test. I do not look at
# ACLs, and I do not check execute permission on the directories above
# the file, so a file can pass here and still be unreachable for that
# user once the parent directory blocks the walk down to it.
def _user_can_read(file_path, user):
    """Mode based read test for a named user, by relation to the file."""
    try:
        entry = pwd.getpwnam(user)
    except KeyError:
        return False
    try:
        st = os.stat(file_path)
    except OSError:
        return False
    mode = stat.S_IMODE(st.st_mode)
    try:
        group_ids = os.getgrouplist(user, entry.pw_gid)
    except Exception:
        group_ids = [entry.pw_gid]
        for group in grp.getgrall():
            if user in group.gr_mem:
                group_ids.append(group.gr_gid)
    if st.st_uid == entry.pw_uid:
        return bool(mode & 0o400)
    if st.st_gid in group_ids:
        return bool(mode & 0o040)
    return bool(mode & 0o004)


def check_file_permissions(file_path, user=None, expected_mode=None):
    """
    Checks if a user has access to a file and if the file has the expected permissions.

    Args:
        file_path (str): The path to the file.
        user (str, optional): The user to check permissions for. Defaults to None (current user).
        expected_mode (int, optional): The expected file mode (e.g., 0o755). Defaults to None (no mode check).

    Returns:
        bool: True if the user has access and the file mode matches (if specified), False otherwise.
    """

    try:
        file_path = os.path.abspath(file_path)

        # Check file existence
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return False

        # Read is the only access I ever test. Write and execute are
        # never checked for any user, so an OK row means readable and,
        # when a mode was given, matching that mode. Nothing more.
        # Check read access. When a user is named, the test is mode based:
        # it uses the owner bits when that user owns the file, the group
        # bits when the file group is one of that user's groups, and the
        # other bits otherwise. Without a named user, os.access for the
        # current process is used.
        if user:
            if not _user_can_read(file_path, user):
                logging.warning(f"User {user} does not have read access to {file_path} by its mode bits")
                return False
        else:
            if not os.access(file_path, os.R_OK):
                logging.warning(f"Current user does not have read access to {file_path}")
                return False


        # Check the file mode if expected_mode is specified
        if expected_mode is not None:
            file_mode = get_file_mode(file_path)
            if file_mode is None:  # Handle error already logged in get_file_mode
                return False

            if file_mode != expected_mode:
                logging.warning(
                    f"File {file_path} has mode {oct(file_mode)}, expected {oct(expected_mode)}"
                )
                return False

        return True  # User has access, and the mode matches (if specified)

    except OSError as e:
        logging.error(f"Error checking permissions for {file_path}: {e}")
        return False


def fix_file_permissions(file_path, expected_mode):
    """
    Attempts to fix the permissions of a file to the expected mode.

    Args:
        file_path (str): The path to the file.
        expected_mode (int): The expected file mode (e.g., 0o755).

    Returns:
        bool: True if the permissions were successfully fixed, False otherwise.
    """
    try:
        file_path = os.path.abspath(file_path)

        os.chmod(file_path, expected_mode)
        logging.info(f"Successfully changed permissions of {file_path} to {oct(expected_mode)}")
        return True
    except OSError as e:
        logging.error(f"Error fixing permissions for {file_path}: {e}")
        return False


def load_exclude_patterns(exclude_file):
    """
    Loads exclude patterns from a file.

    Args:
        exclude_file (str): Path to the file containing exclude patterns.

    Returns:
        pathspec.PathSpec: A PathSpec object containing the exclude patterns, or None if an error occurred.
    """
    try:
        with open(exclude_file, "r") as f:
            patterns = [line.strip() for line in f if line.strip()]  # Read and filter empty lines
        return pathspec.PathSpec(patterns)
    except FileNotFoundError:
        logging.error(f"Exclude file not found: {exclude_file}")
        return None
    except OSError as e:
        logging.error(f"Error reading exclude file: {e}")
        return None


def main():
    """
    Main function to execute the permission consistency checker.
    """
    args = setup_argparse()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Input validation: Check if the user-provided path is valid
    if not os.path.exists(args.path):
        logging.error(f"Path does not exist: {args.path}")
        sys.exit(ERROR_FILE_NOT_FOUND)

    # Input validation: Validate that expected_mode is a valid octal integer.
    expected_mode = None
    if args.expected_mode:
        try:
            expected_mode = int(args.expected_mode, 8)
            # Applying a bitwise AND operation with DEFAULT_FILE_MODE_MASK 
            # ensures that the provided mode respects existing system restrictions.
            # The mask quietly strips setuid, setgid, and sticky bits.
            # Asking for 4755 checks and fixes against 755 instead, with
            # no warning that the special bits were dropped.
            expected_mode &= DEFAULT_FILE_MODE_MASK
            logging.debug(f"Parsed expected mode: {oct(expected_mode)}")
        except ValueError:
            logging.error("Invalid expected mode. Must be an octal integer (e.g., 755).")
            sys.exit(ERROR_INVALID_ARGUMENT)


    if args.fix_permissions and expected_mode is None:
        print("Fixing requires an expected mode: use --expected-mode.")
        logging.error("Fixing requires an expected mode: use --expected-mode.")
        sys.exit(ERROR_INVALID_ARGUMENT)

    if args.user:
        try:
            pwd.getpwnam(args.user)
        except KeyError:
            print(f"User not found: {args.user}")
            logging.error(f"User not found: {args.user}")
            sys.exit(ERROR_USER_NOT_FOUND)

    # Load exclude patterns if an exclude file is provided.
    exclude_spec = None
    if args.exclude_file:
        exclude_spec = load_exclude_patterns(args.exclude_file)
        if exclude_spec is None:
            sys.exit(1)

    console = Console()
    table = Table(title="Permission Consistency Check")
    table.add_column("File Path", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Expected Mode", style="green")
    table.add_column("Actual Mode", style="yellow")

    inconsistent_count = 0
    fixed_count = 0
    total_files = 0

    def process_entry(entry_path):
        nonlocal inconsistent_count, fixed_count, total_files
        if exclude_spec and exclude_spec.match_file(entry_path):
            logging.info(f"Skipping excluded file: {entry_path}")
            return
        total_files += 1
        has_access = check_file_permissions(entry_path, args.user, expected_mode)
        actual_mode = get_file_mode(entry_path)
        expected_mode_str = oct(expected_mode) if expected_mode else "Any"
        actual_mode_str = oct(actual_mode) if actual_mode is not None else "N/A"
        if has_access:
            status = "OK"
        else:
            # A successful chmod is counted as fixed without a recheck.
            # If the mode now matches but the named user still cannot
            # read the file, the row says Fixed and the run exits 0.
            if args.fix_permissions and expected_mode is not None and fix_file_permissions(entry_path, expected_mode):
                status = "Fixed"
                fixed_count += 1
            else:
                status = "Inconsistent"
                inconsistent_count += 1
        if args.report_inconsistencies or status != "OK":
            table.add_row(entry_path, status, expected_mode_str, actual_mode_str)

    if os.path.islink(args.path):
        logging.info(f"Skipping symlink: {args.path}")
        print(f"Skipping symlink: {args.path}")
    elif os.path.isfile(args.path):
        process_entry(args.path)
    else:
        # Walk the directory tree. The walk is recursive by default.
        # Each directory, including the root, is checked as its own row.
        # Symlinks are skipped entirely, in check and fix modes alike.
        to_check = []
        def collect(dir_path, depth):
            to_check.append(dir_path)
            try:
                entries = sorted(os.listdir(dir_path))
            except OSError as e:
                logging.error(f"Error reading directory {dir_path}: {e}")
                return
            for name in entries:
                entry_path = os.path.join(dir_path, name)
                if os.path.islink(entry_path):
                    logging.info(f"Skipping symlink: {entry_path}")
                    print(f"Skipping symlink: {entry_path}")
                    continue
                if os.path.isdir(entry_path):
                    if args.recursive:
                        collect(entry_path, depth + 1)
                    else:
                        if depth == 0:
                            to_check.append(entry_path)
                elif os.path.isfile(entry_path):
                    if args.recursive or depth == 0:
                        to_check.append(entry_path)
        # An empty directory, with no entries at all, is a run that
        # checked nothing for the no files checked rule in decision 5.
        try:
            _root_entries = os.listdir(args.path)
        except OSError:
            _root_entries = ["x"]
        if _root_entries:
            collect(args.path, 0)
        for entry_path in to_check:
            process_entry(entry_path)

    if args.report_inconsistencies:
        console.print(table)
    console.print(f"Total files checked: {total_files}")
    console.print(f"Files with inconsistent permissions: {inconsistent_count}")
    console.print(f"Files fixed: {fixed_count}")

    if total_files == 0:
        print("No files checked.")
        sys.exit(1)

    if inconsistent_count > 0:
        sys.exit(ERROR_INCONSISTENT_PERMISSIONS)
    else:
        sys.exit(0)  # Success, including when every inconsistency was fixed


if __name__ == "__main__":
    main()