from distutils.core import setup

setup(
    name='hl_crypto',
    version='0.4.3',
    packages=['hl_crypto'],
    url='https://github.com/hyperledger/indy-crypto',
    license='MIT/Apache-2.0',
    author='Vyacheslav Gudkov',
    author_email='vyacheslav.gudkov@dsr-company.com',
    description='This is the official wrapper for Hyperledger Indy Crypto library (https://www.hyperledger.org/projects).',
    install_requires=['pytest'],
    tests_require=['pytest']
)
