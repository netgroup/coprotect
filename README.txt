Follow these steps to launch docker containers for simulate application:
1) Install docker
2) Open terminal and place in project folder. For each dockerfile in directory open a screen:
    2.2) Execute command "docker build -f [DOCKERFILE] -t [IMAGE_NAME] ."
    2.3) Execute command "docker run -ti [Client only: -e DISPLAY=$DISPLAY] --name [CONTAINER_NAME] [IMAGE_NAME]"

######
Running the cloud provider app

docker build -f CloudProvider_Dockerfile -t cloudprovider:v0.1 .
docker run -ti --name cloudprovider cloudprovider:v0.1



Running the company app

docker build -f Company_Dockerfile -t company:v0.1 .
docker run -ti --name company company:v0.1



Running the client app

docker build -f Client_Dockerfile -t client:v0.1 .
docker run -ti -p 5002:5002 --name client client:v0.1
