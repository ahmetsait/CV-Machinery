#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import abc
import argparse
import base64
import os
import shlex
import subprocess
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from glob import glob
from itertools import chain
from os.path import *
from threading import Condition, Event, RLock, Semaphore, Thread
from types import *
from typing import *

import jinja2 as j2
import yaml
from watchdog.observers import Observer

from common import *
from merge import *


class JinjaLoader(j2.BaseLoader):
	def __init__(
		self,
		template_path: str,
		enable_includes: bool = True,
		encoding: str | None = "utf-8",
	) -> None:
		self.template_path = template_path
		self.enable_includes = enable_includes
		self.encoding = encoding
		self.included_files = set[str]()
	
	def get_source(self, environment: j2.Environment, template: str) -> tuple[str, str, Callable[[], bool]]:
		if not self.enable_includes and template != self.template_path:
			self.included_files.add(template)
			return "", template, lambda: False
		
		try:
			with open(template, encoding=self.encoding) as f:
				contents = f.read()
		except FileNotFoundError:
			raise j2.TemplateNotFound(template, f"{template!r} not found.")
		
		mtime = getmtime(template)
		
		def uptodate() -> bool:
			try:
				return getmtime(template) == mtime
			except OSError:
				return False
		
		if template != self.template_path:
			self.included_files.add(template)
		return contents, template, uptodate


def get_template_includes(template_path: str, context: Any) -> Iterable[str]:
	jl = JinjaLoader(template_path, enable_includes=False)
	je = j2.Environment(trim_blocks=True, lstrip_blocks=True, undefined=j2.Undefined, loader=jl)
	jt = je.get_template(template_path)
	try:
		js = jt.stream(context)
		js.dump(os.devnull, errors="ignore")
	except j2.TemplateError:
		pass
	return jl.included_files


class BuildFailure(Exception):
	def __init__(self, cmd: list[str], returncode: int, *args: Any):
		super().__init__(*args)
		self.cmd = cmd
		self.returncode = returncode


@dataclass
class TaskNode:
	inputs: set[str]
	outputs: set[str]
	
	#task_done: Event = field(default_factory=Event, kw_only=True)
	#task_msg: str = field(default="", init=False)
	task_lock: RLock = field(default_factory=RLock, init=False)
	task_exitcode: int | None = field(default=None, init=False)
	
	def __hash__(self) -> int:
		return id(self)
	
	def run(self, semaphore: Semaphore, file_cache: FileCache) -> int:
		with self.task_lock:
			if self.task_exitcode is not None:
				return self.task_exitcode
			with semaphore:
				#logln_info("Building: %s", single(self.outputs))
				exitcode = self._run(file_cache)
			if exitcode != 0:
				for i in filter(isfile, self.outputs):
					os.remove(i)
			return exitcode
	
	@abc.abstractmethod
	def _run(self, file_cache: FileCache) -> int:
		raise NotImplementedError()


@dataclass
class CommandTaskNode(TaskNode):
	command: list[str]
	#command_stdout: str = field(default="", init=False)
	#command_stderr: str = field(default="", init=False)
	
	def __hash__(self) -> int:
		return super().__hash__()
	
	def _run(self, file_cache: FileCache) -> int:
		cmd = shlex.join(self.command)
		logln_info("%s", cmd)
		proc = subprocess.run(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.task_exitcode = proc.returncode
		if proc.returncode != 0:
			logln_info("%s\nCommand failed with exit status: %s", cmd, proc.returncode)
			return self.task_exitcode
		return 0


@dataclass
class Base64TaskNode(TaskNode):
	input_path: str
	output_path: str
	
	def __hash__(self) -> int:
		return super().__hash__()
	
	def _run(self, file_cache: FileCache) -> int:
		try:
			logln_info("Base64 encoding: %s > %s", shlex.quote(self.input_path), shlex.quote(self.output_path))
			
			b64: bytes
			with open(self.input_path, "rb") as ifd:
				b64 = base64.b64encode(ifd.read())
			with open(self.output_path, "wb") as ofd:
				ofd.write(b64)
			
			self.task_exitcode = 0
			return 0
		
		except Exception as ex:
			logln_info("Base64 conversion failed: %s", traceback.format_exc())
			self.task_exitcode = 1
			return 1


@dataclass
class JinjaTaskNode(TaskNode):
	template_path: str
	output_path: str
	data_file: str
	
	def __hash__(self) -> int:
		return super().__hash__()
	
	def _run(self, file_cache: FileCache) -> int:
		try:
			logln_info("Rendering jinja template: %s > %s", shlex.quote(self.template_path), shlex.quote(self.output_path))
			
			jl = JinjaLoader(self.template_path)
			je = j2.Environment(trim_blocks=True, lstrip_blocks=True, undefined=j2.StrictUndefined, loader=jl)
			jt = je.get_template(self.template_path)
			
			context = load_recursive(self.data_file, file_cache)[0]
			
			result = jt.render(context)
			with open(self.output_path, "w") as fd:
				fd.write(result)
			
			#node.inputs.clear()
			#node.inputs.add(node.template_path)
			#node.inputs.update(node.data_files)
			#node.inputs.update(jl.included_files)
			
			self.task_exitcode = 0
			return 0
		
		except Exception as ex:
			logln_info("Jinja generation failed: %s", traceback.format_exc())
			self.task_exitcode = 1
			return 1


@dataclass
class DependencyGraph:
	nodes: set[TaskNode]
	output_map: dict[str, TaskNode]
	input_map: dict[str, set[TaskNode]]
	target_nodes: set[TaskNode]


def build_dependency_graph(
	file_cache: FileCache,
	*,
	cv_name: str = "CV",
	data_dir: str = "data",
	style_dir: str = "style",
	base64_dir: str = "base64",
	template_dir: str = "template",
	output_dir: str = "out",
	this_deps: list[str] = [__file__],
) -> DependencyGraph:
	
	nodes = set[TaskNode]()
	output_map = dict[str, TaskNode]()
	input_map = dict[str, set[TaskNode]]()
	target_nodes = set[TaskNode]()
	
	out_node: TaskNode
	
	for in_path in (join(base64_dir, p) for p in os.listdir(base64_dir) if not p.endswith(".b64")):
		out_path = in_path + ".b64"
		out_node = Base64TaskNode(
			set(this_deps + [in_path]),
			set([out_path]),
			in_path,
			out_path,
		)
		
		output_map[out_path] = out_node
		
		if in_path not in input_map:
			input_map[in_path] = set[TaskNode]()
		input_map[in_path].add(out_node)
		
		nodes.add(out_node)
	
	for template_path in glob(join(template_dir, "**", "*.jinja"), recursive=True):
		base = basename(template_path)
		base = splitext(base)[0] # Strip .jinja
		stem, ext = splitext(base) # Split .html
		
		yaml_dir = join(data_dir, stem)
		yaml_files = chain.from_iterable([join(root, file) for file in files] for root, _, files in os.walk(yaml_dir)) # Flatten
		for yaml_file in yaml_files:
			yaml_data, yaml_data_deps = load_recursive(yaml_file)
			
			yaml_relative_path = relpath(yaml_file, yaml_dir)
			yaml_path_slugified = splitext(yaml_relative_path.replace(os.sep, "-"))[0]
			out_stem = "-".join([cv_name, stem, yaml_path_slugified])
			out_path = join(output_dir, out_stem + ext)
			out_node = JinjaTaskNode(
				set(yaml_data_deps + this_deps + [template_path]),
				set([out_path]),
				template_path,
				out_path,
				yaml_file,
			)
			
			out_node.inputs.update(get_template_includes(template_path, yaml_data))
			
			output_map[out_path] = out_node
			
			for input_path in out_node.inputs:
				if input_path not in input_map:
					input_map[input_path] = set[TaskNode]()
				input_map[input_path].add(out_node)
			
			nodes.add(out_node)
			target_nodes.add(out_node)
			
			if out_path.endswith(".html"):
				html_path = out_path
				pdf_path = join(output_dir, out_stem + ".pdf")
				pdf_node = CommandTaskNode(
					set(this_deps + [html_path]),
					set([pdf_path]),
					["google-chrome", "--headless", "--disable-gpu", "--print-to-pdf=" + pdf_path, "--no-pdf-header-footer", html_path],
				)
				
				output_map[pdf_path] = pdf_node
				
				if html_path not in input_map:
					input_map[html_path] = set[TaskNode]()
				input_map[html_path].add(pdf_node)
				
				nodes.add(pdf_node)
				target_nodes.add(pdf_node)

	return DependencyGraph(nodes, output_map, input_map, target_nodes)


def build_nodes(nodes: Iterable[TaskNode], graph: DependencyGraph, semaphore: Semaphore, file_cache: FileCache) -> bool:
	threads = list[Thread]()
	for n in nodes:
		t = Thread(target=lambda: build_node(n, graph, semaphore, file_cache), daemon=True)
		threads.append(t)
		t.start()
	for t in threads:
		t.join()
	return all(n.task_exitcode == 0 for n in nodes)


def build_node(node: TaskNode, graph: DependencyGraph, semaphore: Semaphore, file_cache: FileCache) -> int:
	try:
		threads = list[Thread]()
		tasks = list[TaskNode]()
		for i in node.inputs:
			if i in graph.output_map:
				dep = graph.output_map[i]
				tasks.append(dep)
				t = Thread(target=lambda: build_node(dep, graph, semaphore, file_cache), daemon=True)
				threads.append(t)
				t.start()
		
		for t in threads:
			t.join()
		
		if any(t.task_exitcode != 0 for t in tasks):
			node.task_exitcode = 1
			for i in filter(isfile, node.outputs):
				os.remove(i)
			return False
		
		otime = min((os.stat(o).st_mtime for o in node.outputs if exists(o)), default=0)
		itime = max((os.stat(i).st_mtime for i in node.inputs if exists(i)), default=datetime.now().timestamp())
		
		if otime > itime:
			#logln_info("Up-to-date: %s", single(node.outputs))
			node.task_exitcode = 0
			return True
		
		for o in node.outputs:
			os.makedirs(dirname(o), exist_ok=True)
		
		exitcode = node.run(semaphore, file_cache)
		return exitcode
	
	except Exception as ex:
		node.task_exitcode = 1
		logln_info("%s", repr(ex))
		return False


def main(args: list[str]) -> int:
	parser = argparse.ArgumentParser(add_help=False, formatter_class=argparse.ArgumentDefaultsHelpFormatter, description="CV Machinery incremental build system.")
	parser.add_argument(
		"-w", "--watch",
		action="store_true",
		default=False,
		help="Watch for file changes and build.",
	)
	parser.add_argument(
		"-j", "--jobs",
		type=int,
		default=(os.cpu_count() or 1),
		help="Maximum number of build tasks running in parallel.",
	)
	parser.add_argument(
		"--color",
		action=argparse.BooleanOptionalAction,
		default="auto",
		help="Control terminal color output.",
	)
	parser.add_argument(
		"-?", "--help",
		action="help",
		help="Show this help text and exit.",
	)
	argv = parser.parse_args(args)
	
	this_path = realpath(__file__)
	this_dir = dirname(this_path)
	this_deps = list(map(
		lambda p: relpath(p, realpath(".")),
		[
			this_path,
			join(this_dir, "common.py"),
			join(this_dir, "merge.py"),
		],
	))
	
	#stdin_isatty = os.isatty(sys.stdin.fileno())
	stdout_isatty = os.isatty(sys.stdout.fileno())
	#stderr_isatty = os.isatty(sys.stderr.fileno())
	
	watch: bool = argv.watch
	jobs: int = argv.jobs
	color: bool = False if os.environ.get("NO_COLOR") is not None else stdout_isatty if argv.color == "auto" else argv.color
	
	cv_name = "CV"
	style_dir = "style"
	data_dir = "data"
	base64_dir = "base64"
	template_dir = "template"
	output_dir = "out"
	
	try:
		sass_handler: GenericWatchHandler | None = None
		sass_cmd = ["sass", style_dir, "--update", "--no-source-map"]
		sass_cmd.append("--color" if color else "--no-color")
		if watch: 
			sass_cmd.append("--watch")
			sass_handler = GenericWatchHandler(sass_cmd, "Sass is watching for changes.")
			sass_handler.start()
		else:
			sass_code = subprocess.run(sass_cmd).returncode
			if sass_code != 0:
				raise BuildFailure(sass_cmd, sass_code)
		
		changes = set[str]()
		cond = Condition()
		
		def file_changed(file: str) -> None:
			with cond:
				changes.add(file)
				cond.notify_all()
		
		event_handler = FSEventHandler(relative_to=".", callback=file_changed)
		observer = Observer()
		file_cache = FileCache()
		semaphore = NullSemaphore() if jobs <= 0 else Semaphore(jobs)
		
		if watch:
			observer.unschedule_all()
			observer.schedule(event_handler, ".", recursive=True)
			observer.start()
		
		while True:
			try:
				graph = build_dependency_graph(
					file_cache,
					cv_name=cv_name,
					data_dir=data_dir,
					style_dir=style_dir,
					base64_dir=base64_dir,
					template_dir=template_dir,
					output_dir=output_dir,
					this_deps=this_deps,
				)
				
				build_nodes(graph.target_nodes, graph, semaphore, file_cache)
			
			except Exception as ex:
				logln_info("%s", traceback.format_exc())
			
			if not watch:
				break
			
			with cond:
				changes.clear()
				logln_info("Watching for changes...")
				cond.wait_for(lambda: any(changes))
				logln_info("Change detected")
				while cond.wait(1.0): pass
				if any((c in this_deps) for c in changes):
					logln_info("Restarting: %s", this_path)
					assert(sass_handler is not None)
					sass_handler.stop()
					sass_handler.join()
					os.execv(this_path, [this_path] + args)
	
	except BuildFailure as ex:
		logln_info("\nBuild Failed: Command %s returned with exit status: %s", shlex.quote(shlex.join(ex.cmd)), ex.returncode)
		return ex.returncode
	
	finally:
		if observer.is_alive():
			observer.stop()
			observer.join()
		if sass_handler is not None:
			sass_handler.stop()
			sass_handler.join()
	
	return 0


if __name__ == "__main__":
	import sys
	try:
		sys.exit(main(sys.argv[1:]))
	except KeyboardInterrupt:
		logln_info("\nInterrupted.")
