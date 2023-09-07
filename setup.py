from setuptools import setup, find_packages

setup(
    name='package2cve',
    version='0.7',
    license='MIT',
    description='Give a hostname to get package CVE or pass a package name plus version',
    author='Fernando Castro',
    author_email='whit3bl0cker@gmail.com',
    url='https://github.com/fernandocastrovilar/package2cve',
    download_url='https://github.com/fernandocastrovilar/package2cve/archive/v_07.tar.gz',
    packages=find_packages(),
    install_requires=[
        'paramiko',
        'Requests',
        'setuptools',
        'version_utils'
    ],
)
