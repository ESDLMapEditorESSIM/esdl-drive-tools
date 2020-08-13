# ESDL Drive command line tool
```esdl-drive.py``` is a command line tool to interact with the ESDL Drive. 
It allows you to upload and download files from the ESDL Drive. As the ESDL Drive
is secured, it is required that you provide proper credentials. The tool will ask 
for these credentials when required.

## Installation & Requirements
The tool is developed for Python v3.4 or higher. If you have python3 installed
you can run the tool by:

```$ ./esdl-drive.py```

If not, try:

```python3 -m esdl-drive [options]```

`esdl-drive.py` requires the following Python packages to be installed:
- requests==2.24.0

These are defined in requirements.txt. Most Python installations have these installed by default.

### Use the Windows executable
There is also a Windows executable for ESDl Drive. You don't need Python or other requirements to run it.

It is located in the `dist/` folder and can be downloaded directly from GitHub using this link: [esdl-drive.exe](https://raw.github.../../)


## Usage
```
Usage:                                                                        
  To upload:   esdl-drive.py [options] <filename_or_folder> <esdl_drive_folder
  To download: esdl-drive.py [options] <esdl_drive_file>                      
Try esdl-drive.py -h for more information                                     
```

### Options
```                                                                              
Options:                                                                      
  --version             show program's version number and exit                
  -h, --help            show this help message and exit                       
  -u FOLDER, --upload-folder=FOLDER                                           
                        Upload folder destination in ESDLDrive, e.g. /Users/edwin/                                         
  -f FILE, --upload-file=FILE                                                 
                        File or folder name to upload from local disk, e.g. EnergySystem.esdl or /files/EnergySystems/ or *       
  -d FILE, --download-file=FILE                                               
                        Download file from ESDLDrive, e.g. /Users/edwin/EnergySystem.esdl                        
  -e URL, --esdldrive-url=URL                                                 
                        The base url of the ESDL Drive 
                        [default: https://drive.esdl.hesi.energy]                       
  -t TOKEN_URL, --token-service=TOKEN_URL                                     
                        The URL of the token service to retrieve an access token to access ESDLDrive 
                        [default: https://idm.hesi.energy/auth/realms/esdl-mapeditor/protocol/openid-connect/token]              
  -l USERNAME, --login-name=USERNAME                                          
                        Username for the connection, if not given it will be asked for                                             
  -p, --print-token     Print the token received from the token service       
  -v, --verbose         Be verbose [default: False]                           
```

# Examples
Upload EnergySystem.esdl to your home folder in ESDL Drive
```
esdl-drive.py EnergySystem.esdl /Users/<your username>/
```

Download the same file again:
```
esdl-drive.py /Users/<your username>/EnergySystem.esdl
```

Upload a folder with files to your projects folder:
```
esdl-drive.py /tmp/energysystems/ /Prjects/<project name>/
```

Upload all files in the current folder to your home folder:
It will automatically filter out *.esdl files, others will be ignored.
```
esdl-drive.py * /Users/<your username>/
```

Upload a file to a different ESDL Drive installation (e.g. the open source version),
by specifying a different token provider (-t) and a different ESDL Drive URL (-e):
```
./esdl-drive.py -v -e http://localhost:9080 -t http://localhost:8080/auth/realms/esdl-mapeditor/protocol/openid-connect/token Test2.esdl /Projects/Test/
```

## Generate executable for Windows
To generate an windows executable do the following
```buildoutcfg
pip install pyInstaller
pyinstaller -F esdl-drive.py
```
This will generate an .exe in the dist folder, which can be run on 64-bit Windows.
