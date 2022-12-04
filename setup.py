#!/usr/bin/env python3
from pathlib import Path

from setuptools import setup

with open("README.md", "r") as f:
    long_description = f.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="speedport-api",
    version="0.2.0",
    author="Andre Basche",
    description="Control Telekom Speedport routers with Python",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url="https://github.com/Andre0512/speedport-api",
    license="MIT",
    platforms="any",
    py_modules=["jeelink-python"],
    package_dir={"": "src"},
    packages=["speedport_api"],
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'speedport = speedport_api.__main__:main',
        ]
    }
)
