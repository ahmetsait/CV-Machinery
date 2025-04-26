<div align="center">

CV Machinery  
![Platforms](https://img.shields.io/badge/platforms-linux-blue) [![Version](https://img.shields.io/github/v/tag/ahmetsait/CV-Machinery?label=version)](https://github.com/ahmetsait/CV-Machinery/tags) [![License](https://img.shields.io/github/license/ahmetsait/CV-Machinery)](COPYING.txt)
===
The CV Build System for Developers
</div>

CV Machinery is a CV build system based on [Jinja2][j] templates geared towards developers. It is mainly developed for CV building but is general enough to be used for all kinds of HTML & PDF document generation.

[j]: https://jinja.palletsprojects.com

Currently CV Machinery only works on Linux. Feel free to discuss if you would like to contribute support for other platforms.

Features
--------
- Flexible & programmable [Jinja2][j] template system.
- Powered by HTML & CSS. Harness the browsers' PDF rendering capabilities.
- Quick feedback. The build system automatically builds and refreshes the browser preview on save.
- Data inheritance. Easily create CV variations without repeating yourself. No need to copy a full document just to tweak some sections.

Installing
----------
### Downloads
CV Machinery requires no compilation so there is no binary release.  
You can just clone the repo:
```sh
git clone https://github.com/ahmetsait/CV-Machinery.git
```
Or download it as a [tarball][tgz] file and extract somewhere suitable.

[tgz]: https://github.com/ahmetsait/CV-Machinery/archive/refs/heads/main.tar.gz

### Dependencies
1.	Chromium to render the resulting HTML to PDF, so make sure [Google Chrome][chrome] is installed and `google-chrome` command is available in your `PATH`. You can also edit `build.py` to use something else like `chromium-browser` instead.
2.	[Sass][sass] to compile SCSS styles to CSS. Make sure `sass` command is available in `PATH`. (Tested with Dart Sass 1.83.0)  
	Sass is not essential and you can remove Sass related commands from `build.py` and `.gitignore` if you intend to use plain css.
3.	Python libraries:
	- [Jinja2](https://pypi.org/project/Jinja2) (tested with v3.1.6)
	- [PyYAML](https://pypi.org/project/PyYAML) (tested with v6.0.2)
	- [watchdog](https://pypi.org/project/watchdog) (tested with v6.0.0)
	- [charset-normalizer](https://pypi.org/project/charset-normalizer) (tested with v3.4.1)
	- [websockets](https://pypi.org/project/websockets) (tested with v15.0.1)
	
	These can be installed using **PIP**:
	```sh
	pip install Jinja2 PyYAML watchdog charset-normalizer websockets
	```
	Or via **APT** if you're on a Debian based system (Ubuntu, Linux Mint, Elementary OS etc.):
	```sh
	sudo apt install --yes python3-jinja2 python3-yaml python3-watchdog python3-charset-normalizer python3-websockets
	```
	You may want to instead create a [Python Virtual Environment][venv] for these dependencies if you would like to keep your global depedencies separate from this project. I have not needed them yet personally.

[sass]: https://sass-lang.com
[chromium-headless]: https://developer.chrome.com/docs/chromium/headless
[chrome]: https://www.google.com/chrome/
[venv]: https://docs.python.org/3/tutorial/venv.html

Documentation
---------------
### Getting Started
Inside the project root folder, run the following command in terminal:
```sh
./build.py
```
And you should see some files generated inside `out/` folder:
```
CV-modern-General-en.html
CV-modern-General-en-np.html
CV-modern-General-en-np.pdf
CV-modern-General-en.pdf
CV-simple-General-en.html
CV-simple-General-en-np.html
CV-simple-General-en-np.pdf
CV-simple-General-en.pdf
```

If everything went well, `out/CV-modern-General-en.pdf` should look like this:

<picture>
<source media="(prefers-color-scheme: dark)" srcset="screenshot/CV-dark.png">
<source media="(prefers-color-scheme: light)" srcset="screenshot/CV-light.png">
<img alt="Fallback image description" src="screenshot/CV-light.png">
</picture>

You can now start creating your own CV by editing [data/modern/General-en.yml](data/modern/General-en.yml). Check out <https://learnxinyminutes.com/yaml> if you need a quick YAML syntax cheat-sheet.

### How It Works
At a high level the build script works like this (roughly):
- Convert files inside `base64` folder to Base64 with `.b64` extension added.
- Compile SCSS styles inside `style` folder to CSS with `sass` command.
- For each Jinja template inside `template/` folder;
	- Strip extensions from template file as `template_name`
	- For each YAML file inside `data/<template_name>/`;
		- Read the YAML (including its inheritance chain) as `context`
		- Render the Jinja template to `out/CV-<template_name>-<yaml_name>.html` using `context` as data
		- Render the PDF from the output of previous step to `out/CV-<template_name>-<yaml_name>.pdf` using headless chrome.

All the above tasks are done incrementally and parallelized by constructing a dependency graph.

### Automatic Build on Save (File Watching)
`--watch` command line option can be used to continuously build outputs on every save:
```sh
./build.py --watch
```

### Live Preview
Some PDF viewers such as [Okular][okular] automatically reload when the file being viewed changes. Browsers however, won't automatically refresh a local HTML file. So CV Machinery comes with a simple file server that injects an auto-refresh script to any HTML file that is being served:
```sh
./serve.py
```
Now you can open <http://localhost:8000> and navigate to `/out/CV-modern-General-en.html` in your browser to view the HTML output.
Combining `./build.py --watch` and `./serve.py` side by side provides the live preview functionality such that your changes trigger an automatic refresh on documents you're viewing on browser.

[okular]: https://okular.kde.org

### Data Inheritance & Merging
CV Machinery includes a data merging algorithm to minimize copy pasting and prevent document "variations" getting out-of-date with the main document.

You can use `merge.py` to debug the merge result:
```sh
./merge.py data.yml
```

#### Terminology

In the rest of the document:
- *Base* refers to the data that is being inherited.
- *Overlay* refers to the data that is being merged on top of *base*.

#### `inherits` List

When the root YAML document includes an `inherits` list, files in this list are recursively merged with the current YAML file. `build.py` looks up files relative to the current working directory.

#### `data` Map

Every YAML data file needs to have `data` key whose value is a map. Keys in this map are made available as variables for use in the corresponding Jinja template.

#### Default Merging Rules

Maps combine all their keys. If base and overlay has the same key their values are recursively merged:
```yaml
# base.yml
data:
  a: a
  b: b
  c:
    x: x
    y: y
  d:
    1: one
    2: two
```
```yaml
# overlay.yml
inherits:
- base.yml
data:
  m: m
  n: n
  c:
    z: z
  d: D
```
```yaml
# Result:
a: a
b: b
c:
  x: x
  y: y
  z: z
d: D
m: m
n: n
```

List values in the same position are recursively merged. If overlay has more items, they are appended as-is. If base has more items than the overlay, they are ignored:
```yaml
# base.yml
data:
  list:
  - a
  - x: x
    y: y
  - k
```
```yaml
# overlay.yml
inherits:
- base.yml
data:
  list:
  - b
  - m: n
```
```yaml
# Result:
list:
- b
- x: x
  y: y
  m: n
```

#### Append Merging Rules `+`

List items of overlay are appended to base if the parent map key starts with `+`:
```yaml
# base.yml
data:
  key:
  - a
  - b
```
```yaml
# overlay.yml
inherits:
- base.yml
data:
  +key:
  - x
  - y: y
```
```yaml
# Result:
key:
- a
- b
- x
- y: y
```

#### Delete Merging Rules `-`

If a map key starts with `-`, it is removed:
```yaml
# base.yml
data:
  key1: a
  key2: b
```
```yaml
# overlay.yml
inherits:
- base.yml
data:
  -key1:
```
```yaml
# Result:
key2: b
```

#### Replace Merging Rules `=`

If the map key starts with `=`, its value overwrites base:
```yaml
# base.yml
data:
  key:
    a: a
    b: b
```
```yaml
# overlay.yml
inherits:
- base.yml
data:
  =key:
    x: x
```
```yaml
# Result:
key:
  x: x
```

#### Restructure Merging Rules `~`

If the map key starts with `~` and its value is a list, values of this list are used as indices that refer to base items/keys.

List ~ list:
```yaml
# base.yml
data:
  key:
  - a
  - b
  - c
```
```yaml
# overlay.yml
inherits:
- base.yml
data:
  ~key:
  - 2
  - 0
```
```yaml
# Result:
key:
- c
- a
```

Map ~ list:
```yaml
# base.yml
data:
  key:
    a: a
    b: b
    c: c
```
```yaml
# overlay.yml
inherits:
- base.yml
data:
  ~key:
  - c
  - a
```
```yaml
# Result:
key:
  c: c
  a: a
```

If the map key starts with `~` and its value is a map, overlay keys are used as indices that refer to base items/keys and then the values are merged.

List ~ map:
```yaml
# base.yml
data:
  key:
  - a: a
  - b: b
  - c: c
```
```yaml
# overlay.yml
inherits:
- base.yml
data:
  ~key:
    2:
      x: x
    0:
      y: y
```
```yaml
# Result:
key:
- c: c
  x: x
- a: a
  y: y
```

Map ~ map:
```yaml
# base.yml
data:
  key:
    a:
      k: k
    b:
      l: l
    c:
      m: m
```
```yaml
# overlay.yml
inherits:
- base.yml
data:
  ~key:
    c:
      x: x
    a:
      y: y
```
```yaml
# Result:
key:
  c:
    m: m
    x: x
  a:
    k: k
    y: y
```

### Designing Templates
Check out the [Jinja2 Template Designer Documentation][jtdd] as well as the default templates' code in this project.

[jtdd]: https://jinja.palletsprojects.com/en/stable/templates/

### Adjusting PDF Page Properties
Check out the MDN documentation for [@page][page] CSS rule.

[page]: https://developer.mozilla.org/en-US/docs/Web/CSS/@page

### Page and Column Break Control
Check out the MDN documentation for [break-after](https://developer.mozilla.org/en-US/docs/Web/CSS/break-after), [break-before](https://developer.mozilla.org/en-US/docs/Web/CSS/break-before) and [break-inside](https://developer.mozilla.org/en-US/docs/Web/CSS/break-inside) CSS properties.

License
-------
CV Machinery is licensed under the [GNU Affero General Public License v3.0](COPYING.txt).
