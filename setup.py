#!/usr/bin/env python

from distutils.core import setup
setup(
  name = 'sgcontrol',
  packages = ['sgcontrol'], # this must be the same as the name above
  version = '0.5',
  description = 'Foolproof AWS security group management',
  author = 'Noah Masur',
  author_email = 'nmasur@wesleyan.edu',
  url = 'https://github.com/nmasur/sgcontrol', # use the URL to the github repo
  download_url = 'https://github.com/nmasur/sgcontrol/archive/0.1.tar.gz',
  keywords = ['aws', 'aws-security', 'devops'], # arbitrary keywords
  classifiers = [],
)
