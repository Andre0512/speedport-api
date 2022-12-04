#!/usr/bin/env python3
from setuptools import setup

setup(
    name="speedport-api",
    version="0.1.1",
    author="Andre Basche",
    description="Control Telekom Speedport routers with Python",
    long_description=open("README.md").read(),
    long_description_content_type='text/markdown',
    url="https://github.com/Andre0512/speedport-api",
    license="MIT",
    platforms="any",
    py_modules=["jeelink-python"],
    package_dir={"": "src"},
    packages=["speedport-api"],
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=["requests", "pycryptodome"],
    entry_points={
        'console_scripts': [
            'speedport = speedport_api.__main__:main',
        ]
    }
)
