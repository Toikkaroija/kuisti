#!/bin/bash

# Install dependencies.
sudo apt update && sudo apt install krb5-user libkrb5-dev python3.10-venv python3-dev build-essential -y

# Make a venv and install all required Python packages.
mkdir venv
python3 -m venv venv
. venv/bin/activate
pip3 install -r requirements.txt
