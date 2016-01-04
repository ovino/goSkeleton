# GO Skeleton
This project is a jumpstart kit for a Golang web apps.

### To get going:

- Clone the project.
    ```
    git clone https://github.com/ausrasul/goSkeleton.git
    ```
- Make a new copy of the start.sh file to my_start.sh with the correct path to the project.
- Source the new start.sh file to get the env variables for golang and beego.
    ```
    source ./my_start.sh 4- Update the config file cd goSkeleton/src/app/conf cp app.conf.sample app.conf
    ```
- Install the following packages:
    ```
    go get github.com/astaxie/beego
    go get github.com/beego/bee
    go get github.com/ausrasul/Go-JWT
    go get github.com/ausrasul/Go-Tim
    go get github.com/markbates/goth
    go get golang.org/x/oauth2
    go get github.com/garyburd/redigo/redis

### Now run the app:
```
cd goSkeleton/src/app bee run
```
Then browse to http://yourhost:3000/ You can change the port in the config file.

Happy coding.

