package controllers

import (
	"github.com/astaxie/beego"
	"github.com/markbates/goth/gothic"
	"github.com/ausrasul/Go-JWT"
	"github.com/ausrasul/Go-Tim"
	"log"
)

type LoginController struct{
	beego.Controller
}

type SecureContent struct {
	beego.Controller
}

func (c *LoginController) mapUrl(){
	q := c.Ctx.Request.URL.Query()
	q.Set("provider", c.Ctx.Input.Param(":provider"))
	c.Ctx.Request.URL.RawQuery = q.Encode()
	return
}

func (c *LoginController) isLoggedIn() bool {
	// Check if the user already have a valid token
	var j goJwt.GOJWT
	
	res := c.Ctx.ResponseWriter
	req := c.Ctx.Request
	u, err := j.ParseToken( &res , req)
	log.Print("UUser:" ,u)
	log.Print("Checking if a token already exist")
	if err == nil {
		log.Print("Yes a token exist")
		return true
	}
	return false
}



func (c *LoginController) ShowLoginPage() {
	c.mapUrl()
	
	// Check if the user already have a valid token
	if c.isLoggedIn(){
		log.Print("Yes a token exist")
		c.Ctx.Redirect(301, "/secure")
		return
	}
	c.Data["LoginProvider"] = "Google+"
	c.TplNames = "login.tpl"
}

func (c *SecureContent) Get() {
	// Check if the user already have a valid token
	var j goJwt.GOJWT
	res := c.Ctx.ResponseWriter
	req := c.Ctx.Request
	u, err := j.ParseToken( &res , req)
	if err != nil {
		log.Print("Invalid token")
		c.Ctx.Redirect(301, "/")
		return
	}
	// print our state string to the console. Ideally, you should verify
	// that it's the same string as the one you set in `setState`
	//fmt.Println("key: ", gothic.)
	log.Print("User: ", u)
	c.Data["Email"] = u["Name"]
	c.TplNames = "index.tpl"
}



func (c *LoginController) TimAuthenticate(){
	//c.mapUrl()
	if c.isLoggedIn(){
		log.Print("Yes a token exist")
		c.Ctx.Redirect(301, "/secure")
		return
	}
	
	// Check if the user already have a valid token
	var j goJwt.GOJWT
	
	res := c.Ctx.ResponseWriter
	req := c.Ctx.Request
	
	// print our state string to the console. Ideally, you should verify
	// that it's the same string as the one you set in `setState`
	//fmt.Println("key: ", gothic.)
	var t tim.TIM
	user, err := t.GetUser(c.Input().Get("username"), c.Input().Get("password"))
	//	gothic.CompleteUserAuth(res, req)
	beego.Debug("Tim User: ", user)
	log.Print("Tim Error: ", err)
	if err != nil {
		log.Print("Invalid token")
		c.Ctx.Redirect(301, "/")
		return
	}

	userAttributes := make (map[string]interface{})
	userAttributes["Name"] = user["cn"]
	userAttributes["Email"] = user["mail"]
	//userAttributes["AccessToken"] = user["AccessToken"]
	
	token, err := j.CreateToken(userAttributes, &res, req)
	if err != nil {
		log.Print(res, err)
		return
	}
	token = token 

	log.Print("Authentication completed")
	c.Ctx.Redirect(301, "/secure")
}

func (c *LoginController) Authenticate(){
	c.mapUrl()
	if c.isLoggedIn(){
		log.Print("Yes a token exist")
		c.Ctx.Redirect(301, "/secure")
		return
	}
	gothic.BeginAuthHandler(c.Ctx.ResponseWriter , c.Ctx.Request)
}

func (c *LoginController) Validate(){
	c.mapUrl()
	if c.isLoggedIn(){
		log.Print("Yes a token exist")
		c.Ctx.Redirect(301, "/secure")
		return
	}
	
	// Check if the user already have a valid token
	var j goJwt.GOJWT
	
	res := c.Ctx.ResponseWriter
	req := c.Ctx.Request
	
	// print our state string to the console. Ideally, you should verify
	// that it's the same string as the one you set in `setState`
	//fmt.Println("key: ", gothic.)
	
	user, err := gothic.CompleteUserAuth(res, req)
	log.Print("GothUser: ", user)
	log.Print("GothError: ", err)
	userAttributes := make (map[string]interface{})
	userAttributes["Name"] = user.Name
	userAttributes["Email"] = user.Email
	userAttributes["AccessToken"] = user.AccessToken
	
	token, err := j.CreateToken(userAttributes, &res, req)
	if err != nil {
		log.Print(res, err)
		return
	}
	token = token 

	log.Print("Authentication completed")
	c.Ctx.Redirect(301, "/secure")
	
}