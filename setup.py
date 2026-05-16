from setuptools import find_packages, setup

from whois_tool import __version__

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="whodis",
    version=__version__,
    author="nvk",
    description="RDAP-first domain intelligence CLI with DNS, IP, TLS, and redirect checks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nvk/whodis",
    packages=find_packages(exclude=["tests", "tests.*"]),
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "whodis=whois_tool.whois_cli:main",
        ],
    },
)
