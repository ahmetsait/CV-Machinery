#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import email
import email.utils
import html
import io
import logging
import mimetypes
import os
import posixpath
import re
import selectors
import shutil
import sys
import threading
import traceback
import urllib
import urllib.parse
from collections import deque
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import *
from os.path import *
from socket import *
from socketserver import BaseServer
from threading import Thread
from types import *
from typing import *

from charset_normalizer import from_bytes
from watchdog.observers import Observer
from websockets.exceptions import ConnectionClosed
from websockets.sync.server import *

from common import *


def official_iana_name(charset: str) -> str:
	if charset.lower() == "shift_jis":
		return "shift_jis"
	else:
		return charset.replace("_", "-")

with open("live.js", "rb") as fd:
	live_reload_js = fd.read()


def url_to_path(url: str | bytes) -> str:
	path = urllib.parse.urlsplit(url).path
	try:
		path = urllib.parse.unquote(path, errors='surrogatepass')
	except UnicodeDecodeError:
		path = urllib.parse.unquote(path)
	return path


def translate_path(path: str, relative_to: str, *, strict: bool = False) -> tuple[str, str]:
	path = realpath(relative_to + "/" + path, strict=strict)
	relative_to = realpath(relative_to, strict=strict)
	if commonpath((relative_to, path)) != relative_to:
		raise FileNotFoundError(path)
	return (path, relpath(path, relative_to))


class LiveHTTPRequestHandler(BaseHTTPRequestHandler):
	
	server_version = "LiveHTTP/0.1"
	extensions_map = _encodings_map_default = {
		".gz": "application/gzip",
		".Z": "application/octet-stream",
		".bz2": "application/x-bzip2",
		".xz": "application/x-xz",
		".yaml": "text/x-yaml",
		".yml": "text/x-yaml",
		".jinja": "text/x-jinja",
		".scss": "text/x-scss",
		".b64": "text/plain",
	}
	
	def __init__(self,
		request: socket | tuple[bytes, socket],
		client_address: Any,
		server: BaseServer,
		*,
		directory: str = ".",
		live_port: int,
	) -> None:
		self.directory = realpath(directory, strict=True)
		self.live_script = b"<script>\n" + live_reload_js.replace(b'##PORT##', str(live_port).encode()) + b"</script>\n"
		self._csp_pattern = re.compile(rb'''<meta\s+http-equiv=(["'])Content-Security-Policy\1\s+content=("[^"]*"|'[^']*')\s*>''', re.IGNORECASE)
		super().__init__(request, client_address, server)

	def log_message(self, format: str, *args: Any) -> None:
		message = format % args
		logger.info(
			"[%s] %s %s",
			self.log_date_time_string(),
			self.address_string(),
			escape_nonprintable(message),
		)
	
	def do_HEAD(self) -> None:
		return self.handle_request(head=True)
	
	def do_GET(self) -> None:
		return self.handle_request()
	
	def handle_request(self, head: bool = False) -> None:
		try:
			request_path = url_to_path(self.path)
			path, _ = translate_path(request_path, self.directory, strict=True)
			stat = os.stat(path)
			if isdir(path):
				if not request_path.endswith("/"):
					# Redirect so that relative urls don't break when trailing slash is missing
					self.send_response(HTTPStatus.MOVED_PERMANENTLY)
					parts = urllib.parse.urlparse(self.path)
					redirect_location = urllib.parse.urlunparse((parts.scheme, parts.netloc, parts.path + '/', parts.params, parts.query, parts.fragment))
					self.send_header("Location", redirect_location)
					self.send_header("Content-Length", "0")
					self.end_headers()
					return
				with io.BytesIO() as buf:
					self.render_directory_index(path, request_path, buf)
					self.send_response(HTTPStatus.OK)
					self.send_header("Content-Type", "text/html; charset=utf-8")
					self.send_header("Content-Length", str(buf.tell()))
					self.send_header("Cache-Control", "no-cache")
					self.send_header("Last-Modified", self.date_time_string(stat.st_mtime))
					self.end_headers()
					if not head:
						self.wfile.write(buf.getvalue())
			else:
				if "If-Modified-Since" in self.headers and "If-None-Match" not in self.headers:
					try:
						ims = email.utils.parsedate_to_datetime(self.headers["If-Modified-Since"])
					except (TypeError, IndexError, OverflowError, ValueError):
						# ignore ill-formed values
						pass
					else:
						if ims.tzinfo is None:
							# obsolete format with no timezone, cf.
							# https://datatracker.ietf.org/doc/html/rfc9110#section-5.6.7
							ims = ims.replace(tzinfo=timezone.utc)
						if ims.tzinfo is timezone.utc:
							# compare to UTC datetime of last modification
							mtime = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
							# remove microseconds, like in If-Modified-Since
							mtime = mtime.replace(microsecond=0)
							if mtime <= ims:
								self.send_response(HTTPStatus.NOT_MODIFIED)
								self.end_headers()
								return
				with open(path, "rb") as fd:
					base = basename(path)
					contents = fd.read()
					mime_type = self.guess_mimetype(base)
					if mime_type == "text/html":
						contents = self._csp_pattern.sub(b"", contents)
						idx = contents.rindex(b'</body>')
						contents = contents[:idx] + self.live_script + contents[idx:]
					content_type = mime_type
					charset: str | None = None
					if content_type.startswith("text/"):
						charset_guess = from_bytes(contents).best()
						if charset_guess is not None:
							charset = official_iana_name(charset_guess.encoding)
						content_type += f"; charset={charset}"
					self.send_response(HTTPStatus.OK)
					self.send_header("Content-Type", content_type)
					self.send_header("Content-Length", str(len(contents)))
					self.send_header("Cache-Control", "no-cache")
					# Doesn't seem to do anything
					#if mime_type == "application/pdf":
					#	self.send_header("Content-Disposition", "inline; filename*=UTF-8''" + urllib.parse.quote(base))
					self.send_header("Last-Modified", self.date_time_string(stat.st_mtime))
					self.end_headers()
					if not head:
						self.wfile.write(contents)
		except BrokenPipeError as ex:
			logger.info("%s", repr(ex))
		except (OSError, FileNotFoundError) as ex:
			self.send_error(HTTPStatus.NOT_FOUND)
		except Exception as ex:
			self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, explain=traceback.format_exc())
	
	def render_directory_index(self, dir: str, request_path: str, output: BinaryIO) -> None:
		entries = os.listdir(dir)
		# Directories first
		entries.sort(key=lambda e: ((0 if isdir(join(dir, e)) else 1), e.casefold()))
		dir_esc = html.escape(request_path, quote=False).encode()
		output.write(b'<!DOCTYPE HTML>\n')
		output.write(b'<html lang="en">\n')
		output.write(b'<head>\n')
		output.write(b'<meta charset="utf-8">\n')
		output.write(b'<title>')
		output.write(dir_esc)
		output.write(b'</title>\n')
		output.write(b'</head>\n')
		output.write(b'<body>\n')
		output.write(b'<h1>')
		output.write(dir_esc)
		output.write(b'</h1>\n')
		output.write(b'<hr>\n')
		output.write(b'<ul>\n')
		for name in entries:
			path = os.path.join(dir, name)
			if isdir(path):
				displayname = ensure_dir_sep(name)
				link = ensure_dir_sep(name)
			else:
				displayname = name
				link = name
			link = urllib.parse.quote(link, errors='surrogatepass')
			displayname = html.escape(displayname, quote=False)
			output.write(b'<li>')
			output.write(b'<a href="')
			output.write(link.encode())
			output.write(b'">')
			output.write(displayname.encode())
			output.write(b'</a>')
			if islink(path):
				linktarget = os.readlink(path)
				linktarget = html.escape(linktarget, quote=False)
				output.write(b' -> ')
				output.write(linktarget.encode())
			output.write(b'</li>\n')
		output.write(b'</ul>\n')
		output.write(b'<hr>\n')
		output.write(self.live_script)
		output.write(b'</body>\n')
		output.write(b'</html>\n')
	
	def guess_mimetype(self, path: str) -> str:
		base, ext = posixpath.splitext(path)
		if ext in self.extensions_map:
			return self.extensions_map[ext]
		ext = ext.lower()
		if ext in self.extensions_map:
			return self.extensions_map[ext]
		guess, _ = mimetypes.guess_type(path)
		if guess:
			return guess
		return 'application/octet-stream'


class DualStackServer(ThreadingHTTPServer):
	
	def __init__(self, server_address, RequestHandlerClass, bind_and_activate: bool = True, *, directory: str = ".", live_port: int) -> None: # type: ignore
		super().__init__(server_address, RequestHandlerClass, bind_and_activate)
		self.directory = directory
		self.live_port = live_port
	
	def server_bind(self) -> None:
		# suppress exception when protocol is IPv4
		with suppress(Exception):
			self.socket.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
		return super().server_bind()
	
	def finish_request(self, request, client_address) -> None: # type: ignore
		self.RequestHandlerClass(request, client_address, self, directory=self.directory, live_port=self.live_port) # type: ignore


class FileServer(Thread):
	
	def __init__(self, address: str, port: int, directory: str, live_port: int) -> None:
		super().__init__()
		#protocol: str = "HTTP/1.0"
		#LiveHTTPRequestHandler.protocol_version = protocol
		addr_info = getaddrinfo(address, port)
		family, type, proto, canonname, sockaddr = next(iter(addr_info))
		DualStackServer.address_family = family
		self.server = DualStackServer(sockaddr[:2], LiveHTTPRequestHandler, directory=directory, live_port=live_port)
		netloc = format_socket_address(self.server.socket)
		self.url = urllib.parse.urlunsplit(("http", netloc, "", "", ""))
	
	def run(self) -> None:
		with self.server:
			logln_info("Live file server listening on %s ...", self.url)
			self.server.serve_forever()
	
	def stop(self) -> None:
		self.server.shutdown()


@dataclass
class NotifyInfo:
	path: str
	notified: bool = False


notify_map = dict[ServerConnection, NotifyInfo]()
cond_reload = ConditionFd()

done = False
cond_exit = ConditionFd()

logger = logging.Logger(__name__, logging.INFO)
logger.addHandler(logging.StreamHandler(sys.stdout))


def websocket_msg_loop(websocket: ServerConnection, msg_queue: deque[str | None], cond_msg: ConditionFd) -> None:
	try:
		for msg in websocket:
			with cond_msg:
				msg_queue.append(msg.decode() if isinstance(msg, bytes) else msg)
				cond_msg.notify_all()
	except ConnectionClosed:
		pass
	finally:
		with cond_msg:
			msg_queue.append(None)
			cond_msg.notify_all()

def websocket_main_loop(websocket: ServerConnection, directory: str = ".") -> None:
	global done
	client_path = translate_path(url_to_path(websocket.request.path), directory)[1] if websocket.request is not None else ""
	notify_info = NotifyInfo(client_path)
	with cond_reload:
		notify_map[websocket] = notify_info
	client_address: str = format_socket_address(websocket.socket, True)
	logger.info("WebSocket client connected: %s on path %s", client_address, client_path)
	msg_queue = deque[str | None]()
	cond_msg = ConditionFd()
	t = Thread(target=websocket_msg_loop, args=(websocket, msg_queue, cond_msg))
	t.start()
	try:
		def process_msg() -> bool:
			while True:
				try:
					msg = msg_queue.popleft()
				except IndexError:
					break
				else:
					if msg is None:
						return True
					else:
						try:
							refresh_time = int(msg)
							mtime = os.stat(client_path).st_mtime_ns / 1_000_000
							if mtime >= refresh_time:
								websocket.send("reload")
								logger.info("%s notified: %s", mtime, refresh_time)
						except:
							pass
			return False
		def process_reload() -> bool:
			if notify_info.notified:
				websocket.send("reload")
				logger.info("%s notified: %s", client_address, client_path)
				notify_info.notified = False
			return False
		def process_exit() -> bool:
			return done
		selector = selectors.DefaultSelector()
		while True:
			with cond_msg, cond_reload, cond_exit:
				if process_msg():
					return
				if process_reload():
					return
				if process_exit():
					return
				# Must be in reverse order to avoid deadlock:
				with cond_exit.select_guard(selector) as token_exit, cond_reload.select_guard(selector) as token_reload, cond_msg.select_guard(selector) as token_msg:
					events = selector.select()
				for key, mask in events:
					if key == token_msg:
						if process_msg():
							return
					elif key == token_reload:
						if process_reload():
							return
					elif key == token_exit:
						if process_exit():
							return
	except ConnectionClosed:
		pass
	finally:
		with cond_reload:
			del notify_map[websocket]
		logger.info("WebSocket client disconnected: %s", client_address)


def main(args: list[str]) -> int:
	global done
	parser = argparse.ArgumentParser(add_help=False, formatter_class=argparse.ArgumentDefaultsHelpFormatter, description="Simple HTTP server with automatic & efficient live reload script injection for HTML files.")
	parser.add_argument(
		"-a", "--address",
		default="localhost",
		help="Address to bind.",
	)
	parser.add_argument(
		"-p", "--port",
		type=int,
		default=8000,
		help="Port number to use.",
	)
	parser.add_argument(
		"-l", "--live-port",
		type=int,
		default=9009,
		help="Port number to use for live reload notifier.",
	)
	parser.add_argument(
		"-d", "--directory",
		default=".",
		help="Root directory to serve content from.",
	)
	parser.add_argument(
		"-v", "--verbose",
		default=0,
		action="count",
		help="Increase verbosity of log messages.",
	)
	parser.add_argument(
		"-?", "--help",
		action="help",
		help="Show this help text and exit.",
	)
	argv = parser.parse_args(args)
	
	#stdin_isatty = os.isatty(sys.stdin.fileno())
	#stdout_isatty = os.isatty(sys.stdout.fileno())
	#stderr_isatty = os.isatty(sys.stderr.fileno())
	
	address: str = argv.address
	port: int = argv.port
	live_port: int = argv.live_port
	directory: str = argv.directory
	verbosity: int = argv.verbose
	
	log_level = logging.WARNING if verbosity <= 0 else logging.INFO if verbosity == 1 else logging.DEBUG
	logger.level = log_level
	
	def file_changed(file: str) -> None:
		logger.debug("File changed: %s", file)
		with cond_reload:
			for notify_info in notify_map.values():
				if notify_info.path == file:
					notify_info.notified = True
			cond_reload.notify_all()
	
	event_handler = FSEventHandler(relative_to=directory, callback=file_changed)
	observer = Observer()
	observer.unschedule_all()
	observer.schedule(event_handler, directory, recursive=True)
	observer.start()
	try:
		file_server = FileServer(address, port, directory, live_port)
		file_server.start()
		try:
			addr_info = getaddrinfo(address, live_port)
			family, type, proto, canonname, sockaddr = next(iter(addr_info))
			with serve(lambda sc: websocket_main_loop(sc, directory), address, live_port, family=family, dualstack_ipv6=True) as server:
				try:
					logln_info("WebSocket server listening on ws://%s ...", format_socket_address(server.socket))
					server.serve_forever()
				finally:
					with cond_exit:
						done = True
						cond_exit.notify_all()
		finally:
			file_server.stop()
	finally:
		observer.stop()
	
	return 0


if __name__ == "__main__":
	import sys
	try:
		sys.exit(main(sys.argv[1:]))
	except KeyboardInterrupt:
		logln_info("\nInterrupted.")
