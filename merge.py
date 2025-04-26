#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import sys
from enum import IntEnum, auto
from itertools import chain
from os.path import *
from types import *
from typing import *

import yaml

from common import *

__all__ = [
	"load_recursive",
	"merge_data",
	"MergeStrategy",
]

def strip_one(s: str, chars: str) -> str:
	if len(s) > 0 and any(c == s[0] for c in chars):
		return s[1:]
	return s


class MergeStrategy(IntEnum):
	DEFAULT = auto()
	APPEND = auto()
	REPLACE = auto()
	RESTRUCTURE = auto()


def merge_data(base: Any, overlay: Any, strategy: MergeStrategy = MergeStrategy.DEFAULT) -> Any:
	CONTROL_CHARS = "~+-="
	if (
		strategy == MergeStrategy.REPLACE or
		overlay is None or
		isinstance(overlay, (int, float, complex, bool, str, bytes, bytearray, memoryview))
	):
		return overlay
	
	if isinstance(overlay, list):
		if isinstance(base, list):
			if strategy == MergeStrategy.APPEND:
				return [merge_data(None, i) for i in chain(base, overlay)]
			if strategy == MergeStrategy.DEFAULT:
				return [merge_data((base[i] if i < len(base) else None), o) for i, o in enumerate(overlay)]
			if strategy == MergeStrategy.RESTRUCTURE:
				def foreach() -> Generator[Any, None, None]:
					for i, o in enumerate(overlay):
						if isinstance(o, int):
							yield merge_data(None, base[o])
						else:
							if i < len(base):
								yield merge_data(base[i], o)
							else:
								yield merge_data(None, o)
				return list(foreach())
		if isinstance(base, dict):
			if strategy == MergeStrategy.RESTRUCTURE:
				return {o:base[o] for o in overlay}
		
		return [merge_data(None, o) for o in overlay]
	
	if isinstance(overlay, dict):
		if isinstance(base, dict):
			if strategy == MergeStrategy.RESTRUCTURE:
				result_dict = dict()
				for key, value in overlay.items():
					if isinstance(key, str):
						lkey = strip_one(key, CONTROL_CHARS)
						if key.startswith("+"):
							result_dict[lkey] = merge_data(base.get(lkey, None), value, MergeStrategy.APPEND) if value is not None else base[lkey]
						elif key.startswith("-"):
							pass
						elif key.startswith("="):
							result_dict[lkey] = merge_data(base.get(lkey, None), value, MergeStrategy.REPLACE)
						elif key.startswith("~"):
							result_dict[lkey] = merge_data(base.get(lkey, None), value, MergeStrategy.RESTRUCTURE) if value is not None else base[lkey]
						else:
							result_dict[lkey] = merge_data(base.get(lkey, None), value, MergeStrategy.DEFAULT) if value is not None else base[lkey]
					else:
						result_dict[key] = merge_data(base.get(key, None), value, MergeStrategy.DEFAULT) if value is not None else base[key]
				return result_dict
			else:
				result_dict = base.copy()
				for key, value in overlay.items():
					if isinstance(key, str):
						lkey = strip_one(key, CONTROL_CHARS)
						if key.startswith("+"):
							result_dict[lkey] = merge_data(result_dict.get(lkey, None), value, MergeStrategy.APPEND)
						elif key.startswith("-"):
							del result_dict[lkey]
						elif key.startswith("="):
							result_dict[lkey] = merge_data(result_dict.get(lkey, None), value, MergeStrategy.REPLACE)
						elif key.startswith("~"):
							result_dict[lkey] = merge_data(result_dict.get(lkey, None), value, MergeStrategy.RESTRUCTURE)
						else:
							result_dict[lkey] = merge_data(result_dict.get(lkey, None), value, MergeStrategy.DEFAULT)
					else:
						result_dict[key] = merge_data(result_dict.get(key, None), value, MergeStrategy.DEFAULT)
				return result_dict
		if isinstance(base, list):
			if strategy == MergeStrategy.RESTRUCTURE:
				result_list = list()
				for key, value in overlay.items():
					if isinstance(key, str):
						lkey = strip_one(key, CONTROL_CHARS)
						ikey = int(lkey)
						if key.startswith("+"):
							result_list.append(merge_data(base[ikey], value, MergeStrategy.APPEND)) if value is not None else base[ikey]
						elif key.startswith("-"):
							pass
						elif key.startswith("="):
							result_list.append(merge_data(base[ikey], value, MergeStrategy.REPLACE))
						elif key.startswith("~"):
							result_list.append(merge_data(base[ikey], value, MergeStrategy.RESTRUCTURE)) if value is not None else base[ikey]
						else:
							result_list.append(merge_data(base[ikey], value, MergeStrategy.DEFAULT)) if value is not None else base[ikey]
					else:
						result_list.append(merge_data(base[key], value, MergeStrategy.DEFAULT)) if value is not None else base[key]
				return result_list
		
		return {k:merge_data(None, v) for k, v in overlay.items()}
	
	raise Exception(f"Cannot merge type {type(overlay)} into {type(base)} using {strategy}.")


def load_recursive(file: str, file_cache: FileCache | None = None) -> tuple[Any, list[str]]:
	if file_cache:
		yml = file_cache.read_yaml(file).parsed_data
	else:
		with open(file, "rb") as fd:
			yml = yaml.load(fd, Loader=yaml.CLoader)
	
	if not isinstance(yml, dict):
		raise Exception(f"{file}: Document is not a dictionary/map.")
	if not "data" in yml:
		raise Exception(f"{file}: Document root does not have 'data' key.")
	if not isinstance(yml["data"], dict):
		raise Exception(f"{file}: Document 'data' is not a dictionary/map.")
	
	data = yml["data"]
	inherits = yml["inherits"] if "inherits" in yml else None
	base: Any = None
	inherited = list[str]([file])
	if inherits is not None:
		for i in inherits:
			loaded = load_recursive(i)
			overlay = loaded[0]
			inherited.extend(loaded[1])
			base = merge_data(base, overlay)
	return (merge_data(base, data), inherited)


def main(argv: list[str]) -> int:
	parser = argparse.ArgumentParser(add_help=False, description="Yaml merger.")
	parser.add_argument(
		"args",
		nargs="*",
		help="Command line arguments to pass through app.",
	)
	parser.add_argument(
		"-?", "--help",
		action="help",
		help="Show this help text and exit.",
	)
	args_namespace = parser.parse_args(argv)
	
	args: list[str] = args_namespace.args
	
	for arg in args:
		data = load_recursive(arg)[0]
		logln_info("---")
		yaml.dump(data, sys.stdout, Dumper=yaml.CDumper, sort_keys=False, allow_unicode=True)
		logln_info("...")
	
	return 0


if __name__ == "__main__":
	import sys
	try:
		sys.exit(main(sys.argv[1:]))
	except KeyboardInterrupt:
		logln_info("\nInterrupted.")
