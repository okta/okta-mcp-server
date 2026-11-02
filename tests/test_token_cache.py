# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Concurrency tests use fake storage only, never the user's OS keyring."""

import multiprocessing
import os
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import keyring.errors
import pytest
from okta_mcp_server.utils.auth import token_cache


def _write_tokens(directory, storage, barrier, active, maximum):
    token_cache._LOCK_DIRECTORY = directory

    def replace_password(_service, _username, password):
        with active.get_lock():
            active.value += 1
            maximum.value = max(maximum.value, active.value)
        try:
            storage.unlink(missing_ok=True)
            time.sleep(0.02)
            # Like SecItemAdd, fail if another writer has already added the item.
            with storage.open("x") as stream:
                stream.write(password)
        finally:
            with active.get_lock():
                active.value -= 1

    with patch.object(token_cache.keyring, "set_password", side_effect=replace_password):
        barrier.wait(timeout=15)
        for index in range(8):
            token_cache.set_password("test-service", "api_token", f"fake-{os.getpid()}-{index}")


def _hold_lock(directory, acquired, release, crash=False):
    token_cache._LOCK_DIRECTORY = directory
    with token_cache._cache_lock():
        acquired.set()
        if crash:
            os._exit(0)
        if not release.wait(timeout=15):
            raise TimeoutError("Test did not release lock holder")


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(token_cache, "_LOCK_DIRECTORY", tmp_path / "locks")
    # Any accidentally unmocked backend operation must fail rather than use Keychain.
    with patch.object(token_cache, "keyring", autospec=True) as backend:
        backend.get_password.side_effect = AssertionError("Mock a fake token read explicitly")
        backend.set_password.side_effect = AssertionError("Mock a fake token write explicitly")
        backend.delete_password.side_effect = AssertionError("Mock a fake token delete explicitly")
        yield backend


def test_competing_processes_cannot_overlap_delete_then_add(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(4)
    active = ctx.Value("i", 0)
    maximum = ctx.Value("i", 0)
    storage = tmp_path / "fake-token"
    processes = [
        ctx.Process(
            target=_write_tokens,
            args=(token_cache._LOCK_DIRECTORY, storage, barrier, active, maximum),
        )
        for _ in range(4)
    ]
    try:
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=20)
        assert [process.exitcode for process in processes] == [0] * 4
        assert maximum.value == 1
        assert storage.read_text().startswith("fake-")
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(timeout=5)


@pytest.mark.parametrize("operation", ["get_password", "set_password", "delete_password"])
def test_all_operations_wait_for_other_process(operation, isolated_cache):
    ctx = multiprocessing.get_context("spawn")
    acquired, release = ctx.Event(), ctx.Event()
    process = ctx.Process(target=_hold_lock, args=(token_cache._LOCK_DIRECTORY, acquired, release))
    backend_method = getattr(isolated_cache, operation)
    backend_method.side_effect = None
    backend_method.return_value = "fake-token" if operation == "get_password" else None
    args = ("test-service", "api_token") + (("fake-token",) if operation == "set_password" else ())
    process.start()
    try:
        assert acquired.wait(timeout=10)
        with pytest.raises(TimeoutError, match="token-cache lock"):
            with token_cache._cache_lock(timeout=0.05):
                pytest.fail("A different process owns the lock")
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(getattr(token_cache, operation), *args)
            try:
                time.sleep(0.15)
                assert not future.done()
                backend_method.assert_not_called()
            finally:
                release.set()
            assert future.result(timeout=5) == backend_method.return_value
        backend_method.assert_called_once_with(*args)
    finally:
        release.set()
        process.join(timeout=5)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
    assert process.exitcode == 0


def test_kernel_releases_lock_after_process_exit():
    ctx = multiprocessing.get_context("spawn")
    acquired, release = ctx.Event(), ctx.Event()
    process = ctx.Process(target=_hold_lock, args=(token_cache._LOCK_DIRECTORY, acquired, release, True))
    process.start()
    try:
        assert acquired.wait(timeout=10)
        process.join(timeout=5)
        assert process.exitcode == 0
        with token_cache._cache_lock(timeout=0.5):
            pass
    finally:
        if process.is_alive():
            process.terminate()
        process.join(timeout=5)


def test_backend_exception_releases_lock(isolated_cache):
    isolated_cache.set_password.side_effect = keyring.errors.PasswordSetError("fake failure")
    with pytest.raises(keyring.errors.PasswordSetError):
        token_cache.set_password("test-service", "api_token", "fake-token")
    isolated_cache.set_password.side_effect = None
    token_cache.set_password("test-service", "api_token", "fake-token")
    assert isolated_cache.set_password.call_count == 2


def test_process_lock_timeout_releases_thread_lock():
    with patch.object(token_cache, "_try_lock", return_value=False):
        with pytest.raises(TimeoutError, match="token-cache lock"):
            with token_cache._cache_lock(timeout=0.05):
                pytest.fail("Must not enter a contended critical section")
    with token_cache._cache_lock(timeout=0.5):
        pass


def test_thread_lock_timeout():
    token_cache._THREAD_LOCK.acquire()
    try:
        with pytest.raises(TimeoutError, match="token-cache lock"):
            with token_cache._cache_lock(timeout=0.05):
                pytest.fail("Must not enter a contended critical section")
    finally:
        token_cache._THREAD_LOCK.release()


def test_lock_file_is_private_persistent_and_contains_no_token(isolated_cache):
    isolated_cache.set_password.side_effect = None
    token_cache.set_password("test-service", "api_token", "fake-sensitive-value")
    lock = token_cache._LOCK_DIRECTORY / "tokens.lock"
    inode = lock.stat().st_ino
    token_cache.set_password("test-service", "api_token", "another-fake-value")
    assert lock.stat().st_ino == inode
    assert lock.read_bytes() == b""
    if os.name != "nt":
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600
        assert stat.S_IMODE(lock.parent.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission and symlink checks")
@pytest.mark.parametrize("unsafe", ["symlink", "permissions"])
def test_rejects_unsafe_lock_directory(tmp_path, unsafe):
    directory = token_cache._LOCK_DIRECTORY
    if unsafe == "symlink":
        target = tmp_path / "target"
        target.mkdir(mode=0o700)
        directory.symlink_to(target, target_is_directory=True)
    else:
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
    with pytest.raises(PermissionError):
        with token_cache._cache_lock():
            pytest.fail("Unsafe directory must not be used")
    assert not token_cache._THREAD_LOCK.locked()
