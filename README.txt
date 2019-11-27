This project implements a Web service to provide a collaborative encryption/decryption scheme. In particular,
when deployed, through HTTP requests, it allows to:
    - upload a plaintext file (known unsupported extensions: all compressed ones), obtaining the encrypted version,
    - upload an encrypted file, obtaining the decrypted version (only if previously encrypted with same tool).
System consists of 3 entity:
    - Client that provides the Web service to interact with the user,
    - Cloud Provider Server that handles the most part of operations:
        - providing encryption keys
        - providing first partial decryption

SYSTEM REQUIREMENTS:
- Architecture: 64-bit host or virtual machine
- OS:           Linux

FILE REQUIREMENTS:
- file to encrypt MUST NOT be compressed
An example can be "clear_file.txt" in the project directory


################ BUILD ################

Follow these steps to launch docker containers for simulate application:

1) Install docker

2) Install docker-compose

3) Open terminal and place in project folder

4) To create containers with docker-compose use command:
	- docker-compose up -d --build                          (ONLY FOR FIRST RUN)
	- docker-compose up -d --build --force-recreate -t 0

4.1) If docker raises some errors:
    - retry command using sudo
    - type on terminal "sudo service docker start" and retry command

5) Open the browser and choose to go to:
    - 172.25.0.4:5002 to see all the available HTTP routes
    - 172.25.0.4:5002/index to use the tool

5) To shutdown containers with docker-compose use command:
	- docker-compose down
