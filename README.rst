#######
deadSFS
#######

.. image:: https://travis-ci.com/nklapste/deadSFS.svg?token=PXHp9tdymHUxZDzfWpfK&branch=master
    :target: https://travis-ci.com/nklapste/deadSFS
    :alt: Build Status

A secure filesystem (SFS) client made in python that can hook into most
existing FTP servers.

Requirements
============

* Python 3.6+

Overview
========

TODO: fill

Installation
============

deadSFS can be installed from source by running:

.. code-block:: bash

    pip install .

Within the same directory as deadSFS's ``setup.py`` file.

Usage
=====

deadSFS-keygen
--------------

After installing deadSFS, and before using the deadSFS shell a private key
must be created first. This can be done by running the following console
command:

.. code-block:: bash

    deadSFS-keygen <output>

This will create a random private key file at the path specified
by ``output``.

deadSFS shell
-------------

After installing deadSFS, its shell can be started by the following console
command:

.. code-block:: bash

    deadSFS <keyfile>


To get additional usage help on starting the deadSFS shell run the following
console command:

.. code-block:: bash

    deadSFS --help
