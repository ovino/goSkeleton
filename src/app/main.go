package main

import (
	_ "app/routers"
	"github.com/astaxie/beego"
	// OAuth authentication packages
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/gplus"
	"github.com/ausrasul/Go-JWT"
	"github.com/gorilla/sessions"
	"log"
)

func main() {
	log.SetFlags(log.LstdFlags|log.Lshortfile)
	beego.SetLogFuncCall(true)
	beego.SessionOn = true
	goth.UseProviders( 
		gplus.New(
			beego.AppConfig.String("CLIENT_ID"),
			beego.AppConfig.String("CLIENT_SECRET"),
			beego.AppConfig.String("CLIENT_CALLBACK"),
		),
	)
	SessionTimeout, err := beego.AppConfig.Int("SESSION_TIMEOUT")
	if err != nil {
		beego.Critical(err)
	}
	SessionRefreshInterval, err := beego.AppConfig.Int("SESSION_REFRESH_INTERVAL")
	if err != nil {
		beego.Critical(err)
	}
	goJwt.Conf = goJwt.JwtConf{
		PrivateKeyFile: beego.AppConfig.String("PrivateKeyFile"),
		PublicKeyFile: beego.AppConfig.String("PublicKeyFile"),
		Algorithm: beego.AppConfig.String("Algorithm"),
		SessionSecret: beego.AppConfig.String("SESSION_SECRET"),
		SessionName: beego.AppConfig.String("SESSION_NAME"),
		SessionTimeout: SessionTimeout,
		SessionRefreshInterval: SessionRefreshInterval,
	}
	goJwt.Configure()
	goJwt.Store = sessions.NewCookieStore([]byte(beego.AppConfig.String("SESSION_SECRET")))
	beego.SetStaticPath( "/public", "static")
	
	beego.Run()
}

