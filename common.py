#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import io
import os
import selectors
import signal
import subprocess
import sys
import threading
from collections import deque
from contextlib import suppress
from dataclasses import dataclass, field
from os.path import *
from selectors import EVENT_READ, BaseSelector, SelectorKey
from socket import *
from threading import Semaphore, Thread
from time import monotonic
from types import *
from typing import *

if TYPE_CHECKING:
	from _typeshed import FileDescriptorLike
	from selectors import _EventMask

import yaml
from watchdog.events import *

__all__ = [
	"chomp",
	"ConditionFd",
	"ensure_dir_sep",
	"escape_nonprintable",
	"EventFd",
	"FileCache",
	"FileCacheInfo",
	"format_socket_address",
	"FSEventHandler",
	"GenericWatchHandler",
	"LockFd",
	"log_error",
	"log_info",
	"logln_error",
	"logln_info",
	"NullSemaphore",
	"quote",
	"requires_quoting",
	"SemaphoreFd",
	"single",
	"to_str",
	"try_parse",
	"wait_multiple_files",
]


def try_parse[T](t: type[T], s: str | bytes) -> T | None:
	try: 
		return t(s) # type: ignore
	except ValueError:
		return None


def to_str(s: str | bytes, encoding: str = "utf-8") -> str:
	if isinstance(s, str):
		return s
	else:
		return s.decode(encoding)


def escape_nonprintable(s: AnyStr) -> str:
	special_bytes = b"\0\a\b\t\n\v\f\r\033"
	letter_bytes = b"0abtnvfrE"
	buf = bytearray()
	if isinstance(s, bytes):
		for b in s:
			if b in special_bytes:
				buf.extend(b"\\")
				buf.append(letter_bytes[special_bytes.index(b)])
			elif not chr(b).isprintable():
				buf.extend(b"\\x")
				buf.extend(format(b, "02x").encode())
			else:
				buf.append(b)
	else:
		special_chars = special_bytes.decode()
		letter_chars = letter_bytes.decode()
		
		for c in s:
			if c in special_chars:
				buf.extend(b"\\")
				buf.append(ord(letter_chars[special_chars.index(c)]))
			elif not c.isprintable():
				buf.extend(b"\\x")
				buf.extend(format(c, "02x").encode())
			else:
				buf.append(ord(c))
	
	return buf.decode()


def requires_quoting(s: AnyStr) -> bool:
	special_bytes = b" !\"#$&'()*,;<>?[\\]^`{|}~"
	if isinstance(s, bytes):
		special_chars = special_bytes
	else:
		special_chars = special_bytes.decode()
	
	for c in s:
		if c in special_chars:
			return True
	
	if isinstance(s, bytes):
		return not s.decode().isprintable()
	else:
		return not s.isprintable()


def quote(s: AnyStr) -> str:
	if not requires_quoting(s):
		if isinstance(s, bytes):
			return s.decode()
		else:
			return s
	return "'" + escape_nonprintable(s).replace("'", "'\"'\"'") + "'"


def chomp(s: AnyStr) -> AnyStr:
	"""Removes final newline from the given string"""
	crlf_bytes = b"\r\n"
	lf_bytes = b"\n"
	if isinstance(s, bytes):
		crlf = crlf_bytes
		lf = lf_bytes
	else:
		crlf = crlf_bytes.decode()
		lf = lf_bytes.decode()
	
	if s.endswith(crlf):
		return s[:-len(crlf)]
	if s.endswith(lf):
		return s[:-len(lf)]
	else:
		return s


def ensure_dir_sep(dir: AnyStr) -> AnyStr:
	if isinstance(dir, str):
		sep = os.sep
	else:
		sep = os.sep.encode()
	if not dir.endswith(sep):
		return dir + sep
	else:
		return dir


def single[T](i: Collection[T]) -> T | Collection[T]:
	return next(iter(i)) if len(i) == 1 else i


def format_socket_address(socket: socket, peer: bool = False) -> str:
	addr: tuple[str, int] = socket.getpeername() if peer else socket.getsockname()
	if socket.family == AF_INET6:
		return f"[{addr[0]}]:{addr[1]}"
	else:
		return f"{addr[0]}:{addr[1]}"


class EventFd:
	
	def __init__(self, flags: int = os.EFD_NONBLOCK) -> None:
		self._fd = os.eventfd(0, flags)
		self._selector = selectors.DefaultSelector()
		self._selector.register(self._fd, selectors.EVENT_READ)
	
	def fileno(self) -> int:
		return self._fd
	
	def is_set(self) -> bool:
		return self.wait(timeout=0)
	
	def set(self) -> None:
		with suppress(BlockingIOError):
			os.eventfd_write(self._fd, 1)
	
	def clear(self) -> None:
		with suppress(BlockingIOError):
			os.eventfd_read(self._fd)
	
	def wait(self, timeout: int | None = None) -> bool:
		return bool(self._selector.select(timeout=timeout))


class SemaphoreFd:
	
	def __init__(self, value: int = 1, flags: int = os.EFD_SEMAPHORE) -> None:
		self._maxvalue = value
		self._fd = os.eventfd(value, flags)
		self._selector = selectors.DefaultSelector()
		self._selector.register(self._fd, selectors.EVENT_READ)
	
	def fileno(self) -> int:
		return self._fd
	
	def acquire(self, blocking: bool = True, timeout: float | None = None) -> bool:
		if not blocking and timeout is not None:
			raise ValueError("can't specify timeout for non-blocking acquire")
		
		if self._selector.select(timeout if blocking else 0):
			value = os.eventfd_read(self._fd)
			if value > self._maxvalue:
				raise RuntimeError("unmatched acquire-release calls detected")
			return True
		return False
	
	def release(self) -> None:
		os.eventfd_write(self._fd, 1)
	
	def locked(self) -> bool:
		return not self._selector.select(timeout=0)
	
	def __enter__(self) -> Self:
		self.acquire()
		return self
	
	def __exit__(self,
		type: type[BaseException] | None,
		value: BaseException | None,
		traceback: TracebackType | None,
	) -> None:
		self.release()


class LockFd(SemaphoreFd):
	
	def __init__(self, reentrant: bool = False, flags: int = 0) -> None:
		super().__init__(1, flags)
		self.reentrant = reentrant
		self._tls = threading.local()
		self._tls.owned = False
		self._refcount = 0
	
	def acquire(self, blocking: bool = True, timeout: float | None = None) -> bool:
		if self.reentrant and self.is_owned():
			self._refcount += 1
			return True
		
		result = super().acquire(blocking, timeout)
		if result:
			self._tls.owned = True
			self._refcount += 1
		return result
	
	def release(self) -> None:
		if self.reentrant and self.is_owned() and self._refcount > 1:
			self._refcount -= 1
			return
		
		self._refcount -= 1
		self._tls.owned = False
		super().release()
	
	def is_owned(self) -> bool:
		return hasattr(self._tls, "owned") and self._tls.owned


class ConditionFd:
	
	def __init__(self, lock: LockFd | None = None):
		if lock is None:
			lock = LockFd(True)
		self._lock = lock
		# Export the lock's acquire() and release() methods
		self.acquire = lock.acquire
		self.release = lock.release
		self.is_owned = lock.is_owned
		self._waiters = deque[LockFd]()
	
	def __enter__(self) -> Self:
		self._lock.__enter__()
		return self
	
	def __exit__(self,
		type: type[BaseException] | None,
		value: BaseException | None,
		traceback: TracebackType | None,
	) -> None:
		self._lock.__exit__(type, value, traceback)
	
	def _get_waiter(self, lockfd_flags: int = 0) -> LockFd:
		waiter = LockFd(True, lockfd_flags)
		waiter.acquire()
		self._waiters.append(waiter)
		return waiter
	
	class Token:
		
		def __init__(self, cond: ConditionFd, sel: BaseSelector, lockfd_flags: int = 0):
			self._cond = cond
			self._sel = sel
			self._flags = lockfd_flags
		
		def __enter__(self) -> SelectorKey:
			if not self._cond.is_owned():
				raise RuntimeError("cannot wait on a token of un-acquired condition")
			
			self._lock = self._cond._get_waiter(lockfd_flags=self._flags)
			self._cond.release()
			return self._sel.register(self._lock, EVENT_READ)
		
		def __exit__(self,
			type: type[BaseException] | None,
			value: BaseException | None,
			traceback: TracebackType | None,
		) -> None:
			self._sel.unregister(self._lock)
			self._cond.acquire()
			try:
				self._cond._waiters.remove(self._lock)
			except ValueError:
				pass
			os.close(self._lock.fileno())
	
	def select_guard(self, sel: BaseSelector, lockfd_flags: int = 0) -> Token:
		return ConditionFd.Token(self, sel, lockfd_flags)
	
	def wait(self, timeout: float | None = None) -> bool:
		if not self.is_owned():
			raise RuntimeError("cannot wait on un-acquired condition")
		
		with self._get_waiter() as waiter:
			if timeout is not None:
				return waiter.acquire(True, timeout)
			else:
				return waiter.acquire(False)
	
	def wait_for[T](self, predicate: Callable[[], T], timeout: float | None = None) -> T:
		endtime = None
		waittime = timeout
		result = predicate()
		while not result:
			if waittime is not None:
				if endtime is None:
					endtime = monotonic() + waittime
				else:
					waittime = endtime - monotonic()
					if waittime <= 0:
						break
			self.wait(waittime)
			result = predicate()
		return result
	
	def notify(self, n: int = 1) -> None:
		if not self.is_owned():
			raise RuntimeError("cannot notify on un-acquired condition")
		
		for i in range(n):
			try:
				waiter = self._waiters.popleft()
			except IndexError:
				break
			try:
				waiter.release()
			except RuntimeError:
				pass
	
	def notify_all(self) -> None:
		self.notify(len(self._waiters))


def wait_multiple_files(events: Iterable[FileDescriptorLike], timeout: int | None = None) -> list[tuple[selectors.SelectorKey, "_EventMask"]]:
	selector = selectors.DefaultSelector()
	for event in events:
		selector.register(event, selectors.EVENT_READ)
	return selector.select(timeout=timeout)


def log_info(msg: str, *args: Any, sep: str = " ") -> None:
	print(msg % args, sep=sep, end="", flush=True)


def logln_info(msg: str, *args: Any, sep: str = " ") -> None:
	print(msg % args, sep=sep, flush=True)


def log_error(msg: str, *args: Any, sep: str = " ") -> None:
	print(msg % args, sep=sep, file=sys.stderr, end="", flush=True)


def logln_error(msg: str, *args: Any, sep: str = " ") -> None:
	print(msg % args, sep=sep, file=sys.stderr, flush=True)


class GenericWatchHandler(Thread):
	def __init__(self, cmd: "subprocess._CMD", text: str):
		super().__init__()
		self.daemon = True
		self.cmd = cmd
		self.text = text
		self.returncode: int | None = None
		proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, encoding="utf-8", bufsize=0)
		assert(isinstance(proc.stdout, io.TextIOWrapper))
		for line in proc.stdout:
			log_info(line)
			if text in line:
				break
		self.proc = proc
		self.stdout = proc.stdout
	
	def run(self) -> None:
		for line in self.stdout:
			if len(chomp(line)) > 0:
				log_info(line)
		self.returncode = self.proc.wait()
	
	def stop(self) -> None:
		self.proc.send_signal(signal.SIGINT)


class FSEventHandler(FileSystemEventHandler):
	def __init__(self, *, relative_to: str, callback: Callable[[str], None]):
		super().__init__()
		self.relative_to = realpath(relative_to)
		self.callback = callback
	
	def handle_change(self, event: FileSystemEvent) -> None:
		if not event.is_directory and event.event_type == EVENT_TYPE_MODIFIED:
			# File modification is better handled with "closed" event
			return
		src_path = relpath(realpath(to_str(event.src_path)), self.relative_to)
		#self.changes.add(src_path)
		self.callback(src_path)
		if event.event_type == EVENT_TYPE_MOVED:
			dest_path = relpath(realpath(to_str(event.dest_path)), self.relative_to)
			#self.changes.add(dest_path)
			self.callback(dest_path)
	
	def on_created(self, event: FileCreatedEvent | DirCreatedEvent) -> None:
		super().on_created(event)
		self.handle_change(event)
	
	#def on_deleted(self, event: FileDeletedEvent | DirDeletedEvent) -> None:
	#	super().on_deleted(event)
	#	self.handle_change(event)
	
	def on_moved(self, event: FileMovedEvent | DirMovedEvent) -> None:
		super().on_moved(event)
		self.handle_change(event)
	
	def on_modified(self, event: FileModifiedEvent | DirModifiedEvent) -> None:
		super().on_modified(event)
		self.handle_change(event)
	
	def on_closed(self, event: FileClosedEvent) -> None:
		super().on_closed(event)
		self.handle_change(event)


@dataclass
class FileCacheInfo:
	mtime: float
	contents: str
	parsed_data: Any = None


class FileCache:
	def __init__(self) -> None:
		self._file_contents = dict[str, FileCacheInfo]()
	
	def read_file(self, path: str) -> FileCacheInfo:
		path = realpath(path)
		current_mtime = 0.0
		if path in self._file_contents:
			info = self._file_contents[path]
			current_mtime = getmtime(path)
			if current_mtime <= info.mtime:
				info.mtime = current_mtime
				return info
		
		with open(path, encoding="utf-8") as fd:
			if current_mtime == 0.0:
				current_mtime = getmtime(path)
			contents = fd.read()
			info = FileCacheInfo(current_mtime, contents)
			self._file_contents[path] = info
			return info
	
	def read_yaml(self, path: str) -> FileCacheInfo:
		info = self.read_file(path)
		info.parsed_data = yaml.load(info.contents, Loader=yaml.CLoader)
		return info
	
	def flush_file(self, path: str) -> bool:
		path = realpath(path)
		if path in self._file_contents:
			del self._file_contents[path]
			return True
		return False
	
	def flush_all(self) -> None:
		self._file_contents.clear()


class NullSemaphore(Semaphore):
	def __init__(self, value: int = 0):
		pass
	
	def acquire(self, blocking: bool = True, timeout: float | None = None) -> bool:
		return True
	
	__enter__ = acquire
	
	def release(self, n: int = 1) -> None:
		pass
	
	def __exit__(self,
		t: type[BaseException] | None,
		v: BaseException | None,
		tb: TracebackType | None,
	) -> None:
		pass
