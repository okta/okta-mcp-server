# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Serialize access to the shared OS keyring, including delete-then-add writes."""

import errno
import os
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import keyring

if os.name == "nt":
    import msvcrt
else:
    import fcntl

_LOCK_DIRECTORY = Path.home() / ".cache" / "okta-mcp-server"
_THREAD_LOCK = threading.Lock()
_LOCK_TIMEOUT = 30.0
_POLL_INTERVAL = 0.05


def _try_lock(fd: int) -> bool:
    try:
        if os.name == "nt":
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
            return False
        raise
    return True


def _unlock(fd: int) -> None:
    if os.name == "nt":
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def _cache_lock(timeout: float = _LOCK_TIMEOUT):
    """Lock a persistent, credential-free file; never unlink a live lock inode."""
    deadline = time.monotonic() + timeout
    if not _THREAD_LOCK.acquire(timeout=max(0, timeout)):
        raise TimeoutError("Timed out waiting for the Okta token-cache lock")
    fd = None
    locked = False
    try:
        _LOCK_DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory = _LOCK_DIRECTORY.lstat()
        if not stat.S_ISDIR(directory.st_mode):
            raise PermissionError("Okta token-cache lock directory must not be a symlink")
        if os.name != "nt" and (directory.st_uid != os.getuid() or directory.st_mode & 0o077):
            raise PermissionError("Okta token-cache lock directory must be private to the current user")
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(_LOCK_DIRECTORY / "tokens.lock", flags, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise PermissionError("Okta token-cache lock must be a regular file")
        if os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise PermissionError("Okta token-cache lock file must be private to the current user")
        while not _try_lock(fd):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for the Okta token-cache lock")
            time.sleep(min(_POLL_INTERVAL, remaining))
        locked = True
        yield
    finally:
        try:
            if locked:
                _unlock(fd)
        finally:
            try:
                if fd is not None:
                    os.close(fd)
            finally:
                _THREAD_LOCK.release()


def get_password(service: str, username: str) -> str | None:
    """Read only after a concurrent replacement has finished."""
    with _cache_lock():
        return keyring.get_password(service, username)


def set_password(service: str, username: str, password: str) -> None:
    """Keep the backend's delete-then-add replacement inside one critical section."""
    with _cache_lock():
        keyring.set_password(service, username, password)


def delete_password(service: str, username: str) -> None:
    """Serialize explicit cleanup with readers and writers."""
    with _cache_lock():
        keyring.delete_password(service, username)
