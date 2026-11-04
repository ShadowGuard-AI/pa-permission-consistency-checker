# pa-permission-consistency-checker

Verifies that permissions on the local filesystem are consistent for the same user or role. Focused on tools for analyzing and assessing file system permissions.

The walk is recursive by default. Use --no-recursive to check only the named directory, its immediate entries, and its immediate subdirectories. The --recursive flag is still accepted. Each directory, including the root directory and each subdirectory, is checked as its own row, along with each file. Symlinks are skipped entirely in the walk, in check and fix modes alike, and each skip is logged, so a fix run never changes a target outside the named tree through a symlink.

Checked, inconsistent, and fixed counts are reported separately. Exit codes: 0 when no inconsistency remains, including when every inconsistency was fixed; 1 for a user not found or when no files were checked; 3 when the path does not exist; 4 when inconsistencies remain; 5 for an invalid argument, including --fix-permissions without --expected-mode, which prints a plain line that fixing requires an expected mode. An empty run, including a directory with no entries at all, prints a no files checked line and exits 1.

When --user names a user, that user is resolved through the system password database before any checking, and an unresolvable user exits 1 with a plain user not found line. When a user is named, the access test is mode based by that user's relation to each file: the owner bits when that user owns the file, the group bits when the file group is one of that user's groups, and the other bits otherwise.

## Install

```
git clone https://github.com/ShadowGuard-AI/pa-permission-consistency-checker.git
cd pa-permission-consistency-checker
pip install -r requirements.txt
```

## Usage

```
python3 main.py [options]
```

## Parameters

- `--user, -u`: The user to check permissions for. If omitted, the script runs with the effective user ID.
- `--path, -p`: The path to check permissions recursively from, default `.` (current directory).
- `--exclude-file, -e`: Path to a file containing file patterns to exclude. Each pattern should be on a new line.
- `--expected-mode, -m`: The expected file mode (for example, `755`, `644`). If not specified, checks any access. Must be an octal integer.
- `--report-inconsistencies, -r`: Report files with inconsistent permissions. If not specified, a summary is provided.
- `--fix-permissions, -f`: Attempt to fix inconsistent permissions. Requires appropriate privileges, and requires `--expected-mode`.
- `--recursive`: Check permissions recursively. Enabled by default if path is a directory.
- `--no-recursive`: Do not check permissions recursively.
- `--debug`: Enable debug logging.

## Verified in this wave

`python3 main.py --help` could not run in this sandbox: it exits 1 at import with `ModuleNotFoundError: No module named 'pathspec'`, because `pathspec` is not installed and installs are not made in this wave. Parameters above are taken from the argument parser in `main.py`, and `main.py` passes `py_compile`. No live check run is claimed.

## License

See LICENSE.
