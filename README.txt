Follow these steps to launch docker containers for simulate application:
1) Install docker
2) Open terminal and place in project folder. For each dockerfile in directory open a screen:
    2.2) Execute command "docker built -f [DOCKERFILE] -t [IMAGE_NAME] ."
    2.3) Execute command "docker run -ti [Client only: -e DISPLAY=$DISPLAY] --name [CONTAINER_NAME] [IMAGE_NAME]"
