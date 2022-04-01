#!/bin/sh -ex

python setup.py install
certbot "$@"
