from setuptools import setup
from setuptools import find_packages

version = '0.0.1'

install_requires = [
    'acme',
    'certbot>=0.15',
]

setup(
    name='certbot-dns-json',
    version=version,
    description="JSON output for external DNS for Certbot",
    url='https://github.com/tsprlng/certbot-dns-json',
    package_data={'certbot-dns-json': ['LICENSE']},
    python_requires='>=3.4',
    classifiers=[
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'Environment :: Plugins',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
    ],

    install_requires=install_requires,
    packages=find_packages(),
    entry_points={
        'certbot.plugins': [
            'dns-json = certbot_dns_json.plugin:Authenticator',
        ],
    },
)
