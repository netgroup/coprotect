INTRODUCTION
Encryption mechanisms solved the problem of protecting data, but it introduced the problem of storing the 
encryption/decryption keys in a secure location. In very critical contexts, managing keys on your own or delegating the 
management to a Cloud Provider (or any other trusted third party) cannot be solutions for the SMEs, because both of them
have some advantages but also some relevant disvantages (e.g. in the case of your own key management, there can be 
disastrous situations if there is a key loss; in the case of Cloud key management, there is the problem of the trust).
In order to try to solve the problems of these solutions, CoProtect builds a new trust model based on the collaboration 
between the company and the Cloud Provider.

DESCRIPTION
This project implements a Web service to provide a collaborative encryption/decryption scheme. In particular, when 
deployed, through HTTP requests, it allows to:
    - upload a plaintext file (known unsupported extensions: all compressed ones), obtaining the encrypted version,
    - upload an encrypted file, obtaining the decrypted version (only if previously encrypted with same tool).
System consists of 3 entities:
    - Client that provides the Web service to interact with the user,
    - Cloud Provider Server that handles the most part of operations:
        - providing encryption keys,
        - providing first partial decryption.
    - Company Server that performs the last partial decryption, returning the full decrypted data.
We provide two decryption modes:
    - the first one emulates the normal case with the Company and the Cloud Provider that make use of their own private 
      key fragments,
    - the second one emulates the disaster case with the Company that makes use of its own private key fragment and the 
      Cloud Provider that uses the protected shared private key fragment. [WARNING: This case is just for demonstration 
      purpose because the password of the protected shared fragment is transmitted among the entities but it is needed a
      more secure way to obtain the password]

SYSTEM REQUIREMENTS:
- Architecture: 64-bit host or virtual machine
- OS:           Linux

FILE REQUIREMENTS:
- it works with "normal" files types (.txt, .csv, .py, etc.),
- file to encrypt MUST NOT be compressed (.zip, .tar, etc.).
An example can be "clear_file.txt" in the project directory

WORKING FEATURES:
- At each iteration only one file can be dropped in the dropzones; you need to refresh the page for the same next 
  operation.
- If Company or Cloud Provider servers fail, ALL THE ENTITIES MUST BE REBOOTED in order to spread the new keys.
- If you want to change the IP addresses and ports of the components, you have to modify the files "Const.py" and 
  "docker-compose.yml".
- If you want to modify HTTP routes, cryptographic parameters and others, you have to modify the file "Const.py".

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
