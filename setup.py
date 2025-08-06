from setuptools import setup, find_packages
import shutil
import sys
import os

# Read the README file for long description
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Check for 2to3 availability
if not shutil.which("2to3"):
    sys.stderr.write("[!] WARNING: 2to3 not found. Python 2 support will be disabled.\n")

setup(
    name='pickle_inspector',
    version='0.1.0',
    description='Static analysis tool to detect insecure deserialization in Python code',
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author='anotherik',
    author_email='anotherik@hotmail.com',
    url='https://github.com/anotherik/pickle_inspector',
    project_urls={
        'Bug Reports': 'https://github.com/anotherik/pickle_inspector/issues',
        'Source': 'https://github.com/anotherik/pickle_inspector',
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Security Engineers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: Software Development :: Testing',
    ],
    keywords='security static-analysis pickle deserialization vulnerability',
    packages=find_packages(),
    py_modules=[
        'cli',
        'analyzer', 
        'ast_parser',
        'indexer',
        'resolver',
        'utils',
        'report',
        'sources_and_sinks'
    ],
    install_requires=[
        'tqdm>=4.64.0',
        'rich>=13.3.0',
        'autopep8>=2.0.0',
    ],
    entry_points={
        'console_scripts': [
            'pickle-inspector=cli:main',
        ],
    },
    python_requires='>=3.7',
    include_package_data=True,
    zip_safe=False,
)
