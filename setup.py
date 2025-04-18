from setuptools import setup

with open('README.md', encoding='utf-8') as f:
    setup(
        name='nmapthon2',
        version='0.1.6',
        packages=['nmapthon2'],
        url='https://github.com/cblopez/nmapthon2',
        license='Apache-2.0',
        author='cblopez',
        author_email='cbarrallopez@gmail.com',
        description='A modern Nmap automation library for Python.',
        long_description=f.read(),
        long_description_content_type='text/markdown',
        classifiers=[
            'Development Status :: 4 - Beta',
            'Programming Language :: Python :: 3 :: Only',
            'Topic :: System :: Networking',
            'Topic :: Software Development :: Libraries :: Python Modules',
            'License :: OSI Approved :: Apache Software License',
        ],
        keywords=['python', 'python3', 'nmap', 'module', 'scan', 'nse', 'port', 'service', 'async', 'network']
    )
