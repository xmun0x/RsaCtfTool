#!/usr/bin/env python

from setuptools import setup

with open("factorize/version.py") as f:
    exec(f.read())

with open('requirements.txt') as requirements:
    required = requirements.read().splitlines()

kwargs = {
    "name": "factorize",
    "version": str(__version__),
    "packages": ["factorize"],
}

setup(**kwargs)
