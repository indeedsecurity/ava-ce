import sys
from setuptools import setup, find_packages


if sys.version_info[0] < 3 or sys.version_info[1] < 5:
    sys.exit('Error: AVA only runs on Python 3.5 and above.')

setup(
    name='ava',
    version='1.0.0',
    packages=find_packages(),
    author='Jonathan Hawes',
    author_email='jhawes@indeed.com',
    install_requires=[
        'bs4==0.0.1',
        'defusedxml==0.5.0',
        'pytest==3.3.1',
        'pytest-cov==2.5.1',
        'pytest-mock==1.6.3',
        'PyYAML==3.12',
        'requests==2.21.0',
        'requests-toolbelt==0.8.0',
        'urllib3==1.26.5'
    ],
    long_description=open('README.md').read(),
    entry_points={
        'console_scripts': [
            'ava = ava.scanner:console'
        ]
    }
)
