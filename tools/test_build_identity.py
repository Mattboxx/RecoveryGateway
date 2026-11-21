"""Check generated identities in ordinary, linked and incomplete checkouts."""
from pathlib import Path
import subprocess
import tempfile

from build_identity import git_identity, write_identity


def git(root, *args):
    return subprocess.check_output(
        ["git", "-C", str(root), *args], stderr=subprocess.PIPE, text=True
    ).strip()


def commit(root):
    git(root, "add", "tracked.txt")
    git(root, "-c", "user.name=Build Identity Test", "-c",
        "user.email=identity@example.invalid", "commit", "-qm", "fixture")
    return git(root, "rev-parse", "--short=12", "HEAD")


def repository(root):
    root.mkdir(parents=True)
    git(root, "init", "-q")
    (root / "tracked.txt").write_text("first", encoding="ascii")
    return commit(root)


with tempfile.TemporaryDirectory(prefix="build-identity-") as tmp:
    work = Path(tmp)
    parent = work / "parent"
    checked = work / "linked"
    header = work / "build/mtg_build_identity.h"
    starting = repository(parent)
    git(parent, "worktree", "add", "--detach", "-q", str(checked))
    dependency = checked / "external/microlink"
    dependency.mkdir(parents=True)
    assert git_identity(dependency) == "unknown"
    dependency.rmdir()
    nested = repository(dependency)

    write_identity(checked, header)
    initial = header.read_text(encoding="ascii")
    assert f'MTG_BUILD_COMMIT "{starting}"' in initial
    assert f'MTG_MICROLINK_COMMIT "{nested}"' in initial
    stamp = header.stat().st_mtime_ns
    write_identity(checked, header)
    assert header.stat().st_mtime_ns == stamp

    (checked / "tracked.txt").write_text("second", encoding="ascii")
    (dependency / "tracked.txt").write_text("dep update", encoding="ascii")
    write_identity(checked, header)
    assert f'MTG_BUILD_COMMIT "{starting}-dirty"' in header.read_text(encoding="ascii")
    assert f'MTG_MICROLINK_COMMIT "{nested}-dirty"' in header.read_text(encoding="ascii")
    final_parent = commit(checked)
    final_dependency = commit(dependency)
    write_identity(checked, header)
    final = header.read_text(encoding="ascii")
    assert f'MTG_BUILD_COMMIT "{final_parent}"' in final
    assert f'MTG_MICROLINK_COMMIT "{final_dependency}"' in final
    assert str(work) not in final
print("PASS: build header refreshes clean and dirty parent/dependency identities in a linked worktree")
