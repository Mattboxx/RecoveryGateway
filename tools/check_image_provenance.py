"""The built image reports the exact source it was built from.

System > About shows the build commit compiled into web_ui.c. A build that
reuses a stale CMake configuration keeps the previous commit id (seen in a
linked worktree on 3.0.1-beta.1), and a dirty tree adds "-dirty". This reads
the actual firmware.bin and compares it with `git rev-parse HEAD` and
`git status`. Usage: check_image_provenance.py <build dir with firmware.bin>
"""
from pathlib import Path
import re
from build_identity import git_identity
import sys

ROOT = Path(__file__).resolve().parents[1]
image = (Path(sys.argv[1]) / 'firmware.bin').read_bytes()
m = re.search(rb'edition\x00([0-9a-f]{12}(?:-dirty)?)\x00', image)
assert m, 'build commit not found next to the edition string'
embedded = m.group(1).decode()
expected = git_identity(ROOT)
dependency = git_identity(ROOT / "external/microlink")
assert embedded == expected, f'image reports {embedded}, source is {expected}'
actual_dependency = re.search(rb'\x00([0-9a-f]{12}(?:-dirty)?)\x00+microlink_commit\x00', image)
assert actual_dependency, 'MicroLink build commit not found in the compiled About literals'
assert actual_dependency.group(1).decode() == dependency, 'firmware MicroLink build identity is stale'
assert all(re.fullmatch(r'[0-9a-f]{12}', x) for x in (expected, dependency)), 'both Git trees must be clean and available'
print(f'PASS: image reports source {embedded} and MicroLink {dependency}, both matching clean checkouts')
