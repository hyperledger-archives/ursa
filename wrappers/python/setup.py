from distutils.core import setup

setup(
    name='python3-indy',
    version='1.0.0',
    packages=['indy.crypto'],
    url='https://github.com/hyperledger/indy',
    license='MIT/Apache-2.0',
    author='Vyacheslav Gudkov',
    author_email='vyacheslav.gudkov@dsr-company.com',
    description='This is the official wrapper for Hyperledger Indy Crypto library (https://www.hyperledger.org/projects).',
    install_requires=[],
    tests_require=['pytest']
)
