#! /usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='process-forest',
    author='Willi Ballenthin',
    version='0.1',
    packages = find_packages(),
    install_requires=[
        'iso8601',
        'lxml',
        'python-evtx'
    ],
    scripts=[
        'src/process_forest.py',
    ],
)
