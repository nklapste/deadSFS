#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""setup.py for the deadchat client"""

import codecs
import os
import re
import sys

from setuptools import setup, find_packages
from setuptools.command.test import test


def find_version(*file_paths):
    with codecs.open(os.path.join(os.path.abspath(os.path.dirname(__file__)), *file_paths), "r") as fp:
        version_file = fp.read()
    m = re.search(r"^__version__ = \((\d+), ?(\d+), ?(\d+)\)", version_file, re.M)
    if m:
        return "{}.{}.{}".format(*m.groups())
    raise RuntimeError("Unable to find a valid version")


VERSION = find_version("client", "__init__.py")


class Pylint(test):
    user_options = [('pylint-args=', 'a', "Arguments to pass to pylint")]

    def initialize_options(self):
        test.initialize_options(self)
        self.pylint_args = "client --persistent=y --rcfile=.pylintrc --output-format=colorized"

    def run_tests(self):
        import shlex
        # import here, cause outside the eggs aren't loaded
        from pylint.lint import Run
        Run(shlex.split(self.pylint_args))


class PyTest(test):
    user_options = [("pytest-args=", "a", "Arguments to pass to pytest")]

    def initialize_options(self):
        test.initialize_options(self)
        self.pytest_args = "-v --cov={}".format("client")

    def run_tests(self):
        import shlex
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(shlex.split(self.pytest_args))
        sys.exit(errno)


def readme():
    with open("README.md", encoding="utf-8") as f:
        return f.read()


setup(
    name="deadchat-client",
    version=VERSION,
    description="",
    long_description=readme(),
    author="Nathan Klapstein",
    author_email="nklapste@ualberta.ca",
    url="https://github.com/nklapste/deadchat",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
    ],
    packages=find_packages(exclude=["test"]),
    include_package_data=True,
    install_requires=[
        "pynacl"
    ],
    tests_require=[
        "pytest>=4.1.0,<5.0.0",
        "pytest-cov>=2.6.1,<3.0.0",
        "pylint>=2.2.2,<3.0.0",
    ],
    entry_points={
        "console_scripts": [
            "client = client.__main__:main",
        ],
    },
    cmdclass={"test": PyTest, "lint": Pylint},
)