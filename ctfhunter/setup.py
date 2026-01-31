"""
CTFHunter Setup
===============

Installation script for CTFHunter.
"""

from setuptools import setup, find_packages
import os

# Read version from VERSION file
version = "1.0.0"
version_file = os.path.join(os.path.dirname(__file__), 'VERSION')
if os.path.exists(version_file):
    with open(version_file, 'r') as f:
        version = f.read().strip()

# Read README for long description
readme_file = os.path.join(os.path.dirname(__file__), 'README.md')
long_description = ""
if os.path.exists(readme_file):
    with open(readme_file, 'r', encoding='utf-8') as f:
        long_description = f.read()

# Read requirements
requirements = [
    'rich>=13.0.0',
    'python-magic>=0.4.27',
]

setup(
    name='ctfhunter',
    version=version,
    author='CTFHunter Team',
    author_email='ctfhunter@example.com',
    description='Professional Kali Linux CTF Automation Tool',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/Prudhvisiva03/ctfhunter',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: Utilities',
    ],
    python_requires='>=3.8',
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'ctfhunter=ctfhunter.cli:main',
        ],
    },
    include_package_data=True,
    keywords='ctf security forensics steganography pentesting kali',
    project_urls={
        'Bug Reports': 'https://github.com/Prudhvisiva03/ctfhunter/issues',
        'Source': 'https://github.com/Prudhvisiva03/ctfhunter',
        'Documentation': 'https://github.com/Prudhvisiva03/ctfhunter#readme',
    },
)
