#!/usr/bin/env bash

NEW_USER=$1
useradd ${NEW_USER}
passwd ${NEW_USER}

NEW_USER_HOME="/var/ftp/ece_422_security_project/home/${NEW_USER}"
mkdir ${NEW_USER_HOME}
chown ${NEW_USER}:${NEW_USER} ${NEW_USER_HOME}
usermod -d ${NEW_USER_HOME} ${NEW_USER}

echo "Added new user ${NEW_USER} to the ftp server"
