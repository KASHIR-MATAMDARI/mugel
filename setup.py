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
    author='yodoski123',    
    author_email='valleyislamicnetwork@gmail.com',
    description='A reverse engineering tool',
    long_description=open('D:\mugel\README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/KASHIR-MATAMDARI/mugel.git',
    classifiers=[
        'Programming Language :: Python :: 3',
        'MIT Licence',
        'Operating System :: OS Independent',
    ],
)
