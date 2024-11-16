from setuptools import setup, find_packages

setup(
    name='mugel',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'pefile',
        'capstone',
        'matplotlib'
    ],
    entry_points={
        'console_scripts': [
            'mugl = mugel.mugel:analyze_file',
        ],
    },
    author='Your Name',
    author_email='your.email@example.com',
    description='A reverse engineering tool',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/mugel',
    classifiers=[
        'Programming Language :: Python :: 3',
        'GNU General Public License v2.0',
        'Operating System :: OS Independent',
    ],
)
