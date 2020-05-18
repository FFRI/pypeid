pypeid
=====================================
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)


Yet another implementation of [PEiD](https://github.com/K-atc/PEiD) with yara-python

Requirements
-------------------------------------
- Python 3.6
- poetry

Install
-------------------------------------

```
$ git clone --recursive https://github.com/FFRI/pypeid.git
$ cd pypeid
$ poetry shell
$ poetry install --no-root
$ poetry build
$ pip install dist/pypeid-0.1.0-py3-none-any.whl
$ python
>>> from pypeid import PEiDScanner
>>> scanner = PEiDScanner()
>>> scanner.scan_file("/mnt/c/Windows/System32/notepad.exe")
{'PE': '64 bit', 'DLL': 'no', 'Packed': 'no', 'Anti-Debug': 'no', 'GUI Program': 'yes', 'Console Program': 'no', 'mutex': 'yes', 'contains base64': 'yes', 'PEiD': ['Microsoft_Visual_Cpp_80_DLL'], 'AntiDebug': []}
```

Run unit test
-------------------------------------

```
$ pytest
=========================================================== test session starts ============================================================
platform linux -- Python 3.6.8, pytest-5.4.1, py-1.8.1, pluggy-0.13.1
rootdir: /mnt/c/Users/ko.nakagawa/Documents/WorkDir/pypeid_temp
collecting 0 items
collected 3 items

tests/test_scanner.py ...                                                                                                            [100%]

============================================================ 3 passed in 54.10s ============================================================
```

Tested platform
-------------------------------------
- Ubuntu 18.04 on WSL

Author
-------------------------------------
Koh M. Nakagawa. &copy; FFRI, Inc. 2020
