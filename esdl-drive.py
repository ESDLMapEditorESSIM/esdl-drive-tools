#!/usr/bin/python3

# This work is based on original code copyrighted by TNO.
# Licensed to TNO under one or more contributer license agreements.
#
# TNO licenses this work to you under the Apache License, Version 2.0
# You may obtain a copy of the license at http://www.apache.org/licenses/LICENSE-2.0
#
# Contributors:
#       TNO             - Ewoud Werkman: Initial implementation
#
# :license: Apache License, Version 2.0

"""
esdl-drive.py is a command line tool to interact with the ESDL Drive.
It allows you to upload and download files from the ESDL Drive. As the ESDL Drive
is secured, it is required that you provide proper credentials. The tool will ask
for these credentials when required.

More info about ESDL at: https://github.com/energytransition/ESDL
"""

import sys
import os
from optparse import OptionParser
import pprint
import requests
import getpass
import datetime
import json
import glob
import pathlib


verbose = False
print_token = False
base_path = '/store/resource'
token_file = '.esdl_drive_token'


def main(argv):

    usage = "\n  To upload:   %prog [options] <filename_or_folder> <esdl_drive_folder>\n" \
              "  To download: %prog [options] <esdl_drive_file>\n" \
            "Try %prog -h for more information"

    parser = OptionParser(usage=usage, version="%prog 1.0")
    parser.add_option("-u", "--upload-folder", dest="u_folder", action="store",
                      help="Upload folder destination in ESDLDrive, e.g. /Users/edwin/", metavar="FOLDER")
    parser.add_option("-r", "--recursive", action="store_true", default=False, dest="recursive",
                      help="Recursively upload a whole folder structure")
    parser.add_option("-f", "--upload-file", dest="u_filename", action="store",
                      help="File or folder name to upload from local disk, e.g. EnergySystem.esdl or /files/EnergySystems/ or *",
                      metavar="FILE")
    parser.add_option("-d", "--download-file", dest="d_filename", action="store",
                      help="Download file from ESDLDrive, e.g. /Users/edwin/EnergySystem.esdl", metavar="FILE")
    parser.add_option("-e", "--esdldrive-url", action="store", type="string", dest="url",
                      default="https://drive.esdl.hesi.energy", help="The base url of the ESDL Drive [default: %default]")
    parser.add_option("-t", "--token-service", action="store", type="string", dest="token_url",
                      default="https://idm.hesi.energy/auth/realms/esdl-mapeditor/protocol/openid-connect/token",
                      help="The URL of the token service to retrieve an access token to access ESDLDrive [default: %default]")
    parser.add_option("-l", "--login-name", action="store", type="string", dest="username",
                      help="Username for the connection, if not given it will be asked for")
    parser.add_option("-p", "--print-token", action="store_true", default=False, dest="printtoken",
                      help="Print the token received from the token service")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False,
                      help="Be verbose [default: %default]")
    (options, args) = parser.parse_args()
    #print('Options',options)
    #print('args', args)
    #print('Argv',argv)

    if options.printtoken:
        global print_token
        print_token = True

    if options.d_filename is None and options.u_filename is None:
        if len(args) == 1:
            # one argument: download
            options.d_filename = args[0]
        elif len(args) == 2:
            # two arguments: upload
            options.u_filename = args[0]
            options.u_folder = args[1]
        else:
            print("Error: missing or wrong command line arguments")
            parser.print_usage()
            sys.exit(1)

    if options.u_filename and options.u_folder is None and len(args) == 1:
        options.u_folder = args[0]

    if (options.d_filename and options.u_filename) or (options.d_filename and options.u_folder):
        print("Error: do not combine upload and download")
        parser.print_usage()
        sys.exit(1)

    if options.verbose:
        global verbose
        verbose = True
        #print(options, args)
        print('File to upload:', options.u_filename)
        print('Folder to upload to:', options.u_folder)
        print('File to download:', options.d_filename)
        print('Verbose:', options.verbose)
        print('Recursive:', options.recursive)
        print('Url:', options.url)
        print('Token endpoint:', options.token_url)
        print('Username:', options.username)
        print('-----------------------------------------------------------------')

    if verbose:
        print("Retrieving token...")
    token = get_token(idm_url=options.token_url, username=options.username, verbose=options.verbose)
    if token is None:
        print("Can't retrieve token from {}".format(options.token_url))
        sys.exit(2)
    if verbose:
        print("Logged in")

    if options.u_folder and options.u_filename:
        folder = options.url + base_path + options.u_folder
        file = options.u_filename
        upload(file_or_folder=file, destination_folder=folder, access_token=token['access_token'], options=options)
    if options.d_filename:
        url = options.url + base_path + options.d_filename
        print('Downloading', url)
        download(url, token['access_token'], options.verbose)


def upload(file_or_folder: str, destination_folder: str, access_token: str, options):
    recursive = options.recursive
    if recursive:
        if '*' in file_or_folder:
            print("Error: recursive option should not use wildcards such as * or *.esdl, this is done automatically.")
            sys.exit(1)
        parent_path = pathlib.Path(file_or_folder).resolve()
        files = glob.glob(file_or_folder + os.path.sep + "**/*.esdl", recursive=True)
    else:
        files = glob.glob(file_or_folder)
        if len(files) > 0:
            parent_path = pathlib.Path(files[0]).parent.resolve()
        else:
            print(f'Error finding ESDL-file {file_or_folder}')
            sys.exit(3)
    local_files = []
    for f in files:
        res = pathlib.Path(f).resolve()
        if res.is_file(): # ignore directories (it's not recursive here anymore)
            if res.suffix == '.esdl':
                rel_file = res.relative_to(parent_path)
                local_files.append(str(rel_file))
    if verbose: print('Local files to upload:', local_files)

    for file_to_upload in local_files:
        local_file = os.path.join(parent_path, file_to_upload)
        remote_file = file_to_upload.replace('\\', '/')
        if destination_folder[-1] == '/':
            destination_folder = destination_folder[:-1]
        if destination_folder.endswith('.esdl') and not options.recursive:
            target_location = destination_folder
        else:
            target_location = destination_folder + '/' + remote_file
        upload_file(local_file, target_location, access_token, verbose)
        # refresh access token if necessary and the file operations take longer than a few minutes
        token = get_token(idm_url=options.token_url, username=options.username, verbose=options.verbose)
        access_token = token['access_token']


def upload_file(file:str, target_location:str, access_token:str, verbose=False):
    try:
        with open(file, 'r') as f:
            print(f'Uploading {file} to: {target_location}')
            headers = dict()
            add_auth_headers(headers, access_token)
            data = f.read()
            r = requests.put(url=target_location, headers=headers, data=data)
            if verbose:
                print('Upload response:', r.status_code, r.reason)
            if not r.ok:
                print('Error uploading {}, reason: {}: {}'.format(file, r.reason, r.text))
                if verbose:
                    print("Headers={}".format(r.headers))
    except Exception as e:
        print("Error: {}".format(e))


def download(url:str, access_token: str, verbose=False):
    fileName = url[url.rindex('/')+1:]
    if verbose: print('Storing download in:', fileName)
    headers = dict()
    add_auth_headers(headers, access_token)
    if verbose:
        print("Downloading", url)
        print(headers)
    response = requests.get(url, headers=headers)
    if verbose:
        print('Response:', response.status_code, response.reason, response.headers)
    if response.ok:
        try:
            with open(fileName, 'w') as file:
                file.write(response.text)
        except Exception as e:
            print(f'Error writing download to {fileName}: {e}')
    else:
        print('Error downloading {}, reason: {}: {}'.format(url, response.reason, response.text))


def get_token(idm_url, username:str, password:str=None, verbose: bool = False ):
    #WHOLE=$( curl -s "$KEYCLOAK_URL" \
    # -H "Content-Type: application/x-www-form-urlencoded" \
    # -d "username=$USERNAME" \
    # -d "password=$PASSWORD" \
    # -d 'grant_type=password' \
    home_folder = os.path.expanduser('~')
    tokenpath = os.path.join(home_folder, token_file)
    try:
        with open(tokenpath, 'r') as tf:
            stored_token = json.loads(tf.read())
            if print_token: print('Old token:', stored_token)
            acquiredAt = stored_token['acquiredAt']
            nowEpoch = int(datetime.datetime.now().timestamp())
            if acquiredAt + stored_token['expires_in'] < nowEpoch:
                # token expired: request new token
                print('Access token expired, requesting a new one')
                # check refresh token
                refresh_time = stored_token['refresh_expires_in']
                if acquiredAt + refresh_time < nowEpoch:
                    #refresh token also expired, get a new one:
                    return get_access_token_from_keycloak(idm_url, username, password, verbose)
                else:
                    return get_refresh_token_from_keycloak(idm_url, stored_token, verbose)
            else:
                return stored_token
    except FileNotFoundError:
        # no stored token yet
        return get_access_token_from_keycloak(idm_url, username, password, verbose)


def get_access_token_from_keycloak(idm_url, username:str, password:str=None, verbose: bool = False):
    if username is None:
        print('Login to ESDLDrive:')
        username = input("Username: ")
    if password is None:
        password = getpass.getpass(prompt="Password: ")
    #headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"username": username, "password": password, "grant_type": "password", "client_id": "curl", 'scope': 'openid profile email microprofile-jwt user_group_path'}
    response = requests.post(idm_url, data=data)
    password = None
    #print(response.status_code, response.request.body)
    if not response.ok:
        print("Error: HTTP status", response.status_code, response.text)
        return None
    token = response.json()
    home_folder = os.path.expanduser('~')
    tokenpath = os.path.join(home_folder, token_file)
    with open(tokenpath, 'w') as tf:
        token['acquiredAt'] = int(datetime.datetime.now().timestamp())
        tf.write(json.dumps(token))
    if print_token:
        print('Token:')
        pprint.pprint(token)
    return token


def get_refresh_token_from_keycloak(idm_url, stored_token, verbose: bool = False):
    if verbose: print('Getting refresh token')
    #data = {"username": username, "password": password, "grant_type": "password", "client_id": "curl", 'scope': 'openid profile email microprofile-jwt user_group_path'}
    data = {"client_id": "curl", 'grant_type' : 'refresh_token', 'refresh_token': stored_token['refresh_token']}
    response = requests.post(idm_url, data=data)
    #print(response.status_code, response.request.body)
    if not response.ok:
        print("Error getting refresh token: HTTP status", response.status_code, response.text)
        return None
    token = response.json()
    home_folder = os.path.expanduser('~')
    tokenpath = os.path.join(home_folder, token_file)
    with open(tokenpath, 'w') as tf:
        token['acquiredAt'] = int(datetime.datetime.now().timestamp())
        tf.write(json.dumps(token))
    if print_token:
        print('Refreshed token:')
        pprint.pprint(token)
    return token


def add_auth_headers(headers: dict, bearer_token: str):
    auth_header = {'Authorization': 'Bearer ' + bearer_token, 'Content-Type': 'application/xml'}
    headers.update(auth_header)


if __name__ == '__main__':
    main(sys.argv)
