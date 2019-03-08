#!/usr/bin/env bash

# Add a new user to the deadSFS FTP server

NEW_USER=$1

useradd ${NEW_USER}
passwd ${NEW_USER}
usermod -a -G ftpuser ${NEW_USER}

FTP_HOME="/var/ftp/ece_422_security_project/home"
usermod -d ${FTP_HOME} ${NEW_USER}

NEW_USER_HOME="${FTP_HOME}/${NEW_USER}"
mkdir ${NEW_USER_HOME}
chown ${NEW_USER}:${NEW_USER} ${NEW_USER_HOME}
chmod 750 ${NEW_USER_HOME}

echo "Added new user ${NEW_USER} to the ftp server"
