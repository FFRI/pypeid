# pypeid

[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)

Yet another implementation of [PEiD](https://github.com/K-atc/PEiD) with yara-python

## Requirements

- Python 3.11
- Poetry 1.2+

## Install

```
$ git clone --recursive https://github.com/FFRI/pypeid.git
$ cd pypeid
$ poetry shell
$ poetry install --no-root
$ poetry build
$ pip install dist/pypeid-0.1.2-py3-none-any.whl
$ python
>>> from pypeid import PEiDScanner
>>> scanner = PEiDScanner()
>>> scanner.scan_file("/mnt/c/Windows/System32/notepad.exe")
{'PE': '64 bit', 'DLL': 'no', 'Packed': 'no', 'Anti-Debug': 'no', 'GUI Program': 'yes', 'Console Program': 'no', 'mutex': 'yes', 'contains base64': 'yes', 'PEiD': ['Microsoft_Visual_Cpp_80_DLL'], 'AntiDebug': []}
```

## Run unit test

```
$ poetry run pytest
================================================= test session starts ==================================================
platform linux -- Python 3.11.2, pytest-7.2.2, pluggy-1.0.0
rootdir: /home/ffri/pypeid
collected 3 items

tests/test_scanner.py ...                                                                                        [100%]

================================================== 3 passed in 1.10s ===================================================
```

## Tested platform

- Ubuntu 22.04 on WSL2 & Python 3.11.2

## Author

Koh M. Nakagawa. &copy; FFRI Security, Inc. 2020-2023
