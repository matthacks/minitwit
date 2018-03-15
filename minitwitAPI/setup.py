from setuptools import setup

setup(
    name='minitwit_api',
    packages=['minitwit_api'],
    include_package_data=True,
    install_requires=[
        'flask',
    ],
    setup_requires=[
        'pytest-runner',
    ],
    tests_require=[
        'pytest',
    ],
)
