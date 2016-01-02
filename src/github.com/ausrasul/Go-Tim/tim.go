package tim

import (
	"errors"
	"fmt"
	"github.com/nmcclain/ldap"
	"github.com/astaxie/beego"
)

var Conf LdapConf

type LdapConf struct {
	Ldap_server string
	Ldap_port   uint16
	Base_dn     string
	Ldap_user   string
	Ldap_pass   string
}

type TIM struct{}

func (t TIM) GetUser(name string, pass string) (map[string]interface{}, error) {
	user := make(map[string]interface{})
	l, err := ldapConnect()
	if err != nil {
		beego.Error("Ldap connection failed, ", err)
		return user, errors.New("LDAP connection failed")
	}
	defer l.Close()

	err = ldapBind(l)
	if err != nil {
		beego.Error("LDAP bind failed, ", err)
		return user, errors.New("LDAP bind failed")
	}
	
	roles, err := getUserRoles(l, name)
	
	if err != nil {
		beego.Error("No rules for this user, ", err)
		return user, errors.New("No roles for this user...")
	}
	user["Roles"] = roles
	
	err = getUserInfo(l, user, name)
	if err != nil {
		beego.Info("Invalid User, ", err)
		return user, errors.New("Invalid User")
	}
	err = authenticate(l, user["DN"].([]string)[0], pass)
	if err != nil {
		beego.Info("Invalid password, ", err)
		return user, errors.New("Invalid Password")
	}

	return user, nil
}

func ldapConnect() (l *ldap.Conn, err error) {
	l, err = ldap.Dial(
		"tcp",
		fmt.Sprintf("%s:%d", Conf.Ldap_server, Conf.Ldap_port),
	)
	if err != nil {
		beego.Error(err)
		return
	}
	return
}

func ldapBind(l *ldap.Conn) (err error) {
	err = l.Bind(Conf.Ldap_user, Conf.Ldap_pass)
	if err != nil {
		beego.Error(err)
		return
	}
	return
}

func getUserInfo(l *ldap.Conn, user map[string]interface{}, name string) (err error) {
	filter := `(uid=` + name + `)`
	search_request := ldap.NewSearchRequest(
		Conf.Base_dn,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways,
		0,
		0,
		false,
		filter,
		[]string{},
		nil)
	sr, err := l.Search(search_request)
	if err != nil {
		beego.Error(err)
		return
	}
	if len(sr.Entries) != 1 {
		beego.Info("Invalid user")
		return errors.New("Invalid User")
	}
	for _, v := range sr.Entries[0].Attributes {
		if v.Name != "userPassword" {
			user[v.Name] = v.Values
		}
	}
	user["DN"] = []string{sr.Entries[0].DN}
	return nil
}

func authenticate(l *ldap.Conn, nameDn string, pass string) (err error) {
	err = l.Bind(nameDn, pass)
	if err != nil {
		beego.Error(err)
		return
	}
	return
}

func getUserRoles(l *ldap.Conn, name string) (roles []string, err error) {
	filter := `(uniqueMember=uid=` + name + `,*)`
	search_request := ldap.NewSearchRequest(
		Conf.Base_dn,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways,
		0,
		0,
		false,
		filter,
		nil,
		nil)
	sr, err := l.Search(search_request)
	if err != nil {
		beego.Error("Error searching for user roles: ", err)
		return
	}

	if len(sr.Entries) < 1 {
		beego.Info("No roles for this user.")
		return []string{}, errors.New("No roles for this user")
	}
	for _, v := range sr.Entries {
		for _, v2 := range v.Attributes {
			if v2.Name == "cn" {
				roles = append(roles, v2.Values[0])
			}
		}
	}
	return
}
