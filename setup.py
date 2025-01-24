from setuptools import setup

setup(
    name='ec2cli',
    version='0.1.0',
    py_modules=['ec2cli'],
    install_requires=[
        'Click',
        'boto3',
        'tabulate',
        'requests',
        'pycryptodome',
        'pick',
        'auto-click-auto'

    ],
    entry_points={
        'console_scripts': [
            'ec2cli = ec2cli:ec2cli',
        ],
    },
)