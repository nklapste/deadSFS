#!/usr/bin/env bash

# Basic directory setup for the deadSFS FTP server

FTP_HOME="/var/ftp/ece_422_security_project/home/"

groupadd ftpuser
mkdir ${FTP_HOME}
chgrp ftpuser ${FTP_HOME}
chmod 775 ${FTP_HOME}
