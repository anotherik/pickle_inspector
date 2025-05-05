from setuptools import setup, find_packages
import shutil
import sys

# Check for 2to3 availability
if not shutil.which("2to3"):
    sys.stderr.write("[!] WARNING: 2to3 not found. Python 2 support will be disabled.\n")

setup(
    name='pickle_inspector',
    version='0.1',
    description='Static analysis tool to detect insecure deserialization in Python code',
    author='Your Name',
    packages=find_packages(),
    install_requires=[
        'tqdm>=4.64.0',
        'rich>=13.3.0',
        'autopep8>=2.0.0',
    ],
    entry_points={
        'console_scripts': [
            'pickle-inspector = cli:main'
        ]
    },
    python_requires='>=3.7',
)
