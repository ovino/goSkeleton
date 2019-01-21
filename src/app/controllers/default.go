package controllers

import (
	"github.com/astaxie/beego"
)

type MainController struct {
	beego.Controller
}

func (c *MainController) Get() {
	c.Data["Website"] = "beego.meeeeee"
	c.Data["Email"] = "astaxie@gmail.com"
	c.TplNames = "index.tpl"
}
