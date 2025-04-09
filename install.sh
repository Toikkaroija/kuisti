#!/bin/bash

# Install dependencies.
python3_version=$(python3 --version | grep -Po '3.(10|\d+)')
apt update && apt install krb5-user libkrb5-dev python${python3_version}-venv python3-dev build-essential -y

# Make a venv and install all required Python packages.
mkdir venv
python3 -m venv venv
. venv/bin/activate
pip3 install -r requirements.txt