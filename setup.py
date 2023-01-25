"""
Scope Validation Tool v1.2.0

Copyright 2022 Scope Validation Tool Contributors, All Rights Reserved

License-Identifier: MIT (SEI)-style

Please see additional acknowledgments (including references to third party source code, object code, documentation and other files) in the license.txt file or contact permission@sei.cmu.edu for full terms.

Created, in part, with funding and support from the United States Government. (see Acknowledgments file).

DM22-0416
"""

from setuptools import find_packages, setup
REQUIRED = ["argparse", "dnspython"]

setup(
    name='recon',
    version='1.2.0',
    description='This is the package to install recon, a scope validation tool',
    author='SEI',
    packages=find_packages(exclude='test-data'),
    entry_points={
        'console_scripts': ['recon=recon.recon:main'],
    },
    install_requires=REQUIRED,
    include_package_data=True,
    license='MIT',
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],


)
