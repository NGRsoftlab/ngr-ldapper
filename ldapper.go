// Copyright 2020 NGR Softlab
//
// Ldap_common - pack with common ldap functions (working with Active Directory).
package ldapper

import (
	"fmt"
	"strings"

	errorCustom "github.com/NGRsoftlab/error-lib"
	"github.com/NGRsoftlab/ngr-logging"

	"github.com/go-ldap/ldap/v3"
)

// /////////////////////////////////////////////
type LdapConn struct {
	host       string
	port       interface{}
	user       string
	password   string
	useTLS     bool
	Connection *ldap.Conn
}

func NewLdapConn(userName, passWord, host string, port interface{}, useTls bool) (*LdapConn, error) {
	var uri string
	uri = fmt.Sprintf("ldap://%s:%v", host, port)
	if useTls {
		uri = fmt.Sprintf("ldaps://%s:%v", host, port)
	}

	conn, err := ldap.DialURL(uri)
	if err != nil {
		logging.Logger.Error(err)
		return nil, errorCustom.GlobalErrors.ErrBadIpOrPort()
	}

	err = conn.Bind(userName, passWord)
	if err != nil {
		logging.Logger.Error(err)
		return nil, errorCustom.GlobalErrors.ErrBadAuthData()
	}

	return &LdapConn{
		host:       host,
		port:       port,
		user:       userName,
		password:   passWord,
		useTLS:     useTls,
		Connection: conn,
	}, nil
}

func (conn *LdapConn) Close() {
	if conn.Connection != nil {
		conn.Connection.Close()
	}
}

///////////////////////////////////////////////

// Test auth in AD.
func TryAccess(userName, passWord, host string, port interface{}, useTls bool) error {
	_, err := NewLdapConn(userName, passWord, host, port, useTls)

	logging.Logger.Info("ldap resp error:", err)
	return err
}

// Test search in AD baseDn path.
func TestBaseDn(userName, passWord, host string, port interface{}, baseDn string, useTls, openLdap bool) error {

	conn, err := NewLdapConn(userName, passWord, host, port, useTls)
	if err != nil {
		logging.Logger.Error(err)
		return err
	}
	defer func() { conn.Close() }()

	filter := FilterGroup

	searchRequest := ldap.NewSearchRequest(
		baseDn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"cn"},
		nil,
	)

	searchResult, err := conn.Connection.Search(searchRequest)
	if err != nil {
		logging.Logger.Error(err)
		return errorCustom.GlobalErrors.ErrBadBaseDn()
	}

	var cn interface{}
	for _, entry := range searchResult.Entries {
		cn = entry.GetAttributeValue("cn")
		break
	}

	if cn == nil {
		logging.Logger.Error("bad search str")
		return errorCustom.GlobalErrors.ErrBadBaseDn()
	}

	return nil
}

// Reading user info from AD.
func ReadUserInfo(userName, domUser, domPassWord, host string,
	port interface{}, baseDn string, useTls, openLdap bool) (UserInfo, error) {

	var inf UserInfo

	conn, err := NewLdapConn(domUser, domPassWord, host, port, useTls)
	if err != nil {
		logging.Logger.Error(err)
		return inf, err
	}
	defer func() { conn.Close() }()

	var filter string
	var attributes = make([]string, 0)

	if openLdap {
		filter = fmt.Sprintf(SearchFilterUserLinux, userName)
		attributes = []string{"cn", "departmentNumber", "mobile", "mail", "title", "jpegPhoto"}
	} else {
		filter = fmt.Sprintf(SearchFilterUserAd, userName)
		attributes = []string{
			"cn",
			"department",
			"mobile",
			"mail",
			"title",
			"thumbnailPhoto",
			"manager",
			"telephoneNumber",
			"streetAddress",
			"l",
			"physicalDeliveryOfficeName",
			"postalCode",
			"co",
			"company",
		}
	}

	searchRequest := ldap.NewSearchRequest(
		baseDn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil,
	)

	searchResult, err := conn.Connection.Search(searchRequest)
	if err != nil {
		logging.Logger.Warning(err)
	}

	if searchResult != nil {
		for _, entry := range searchResult.Entries {
			inf.CN = entry.GetAttributeValue("cn")
			inf.Mobile = entry.GetAttributeValue("mobile")
			inf.Mail = entry.GetAttributeValue("mail")
			inf.Title = entry.GetAttributeValue("title")

			inf.Manager = entry.GetAttributeValue("manager")
			inf.Phone = entry.GetAttributeValue("telephoneNumber")
			inf.Address = entry.GetAttributeValue("streetAddress")
			inf.City = entry.GetAttributeValue("l")
			inf.Room = entry.GetAttributeValue("physicalDeliveryOfficeName")
			inf.Index = entry.GetAttributeValue("postalCode")
			inf.Country = entry.GetAttributeValue("co")
			inf.Company = entry.GetAttributeValue("company")

			if openLdap {
				inf.Department = entry.GetAttributeValue("departmentNumber")
				inf.Photo = entry.GetAttributeValue("jpegPhoto")
			} else {
				inf.Department = entry.GetAttributeValue("department")
				inf.Photo = entry.GetAttributeValue("thumbnailPhoto")
			}
		}
	}

	// for no Name users cases
	if inf.CN == nil {
		inf.CN = userName
	}

	return inf, nil
}

/////////////////////////////////////////
/////////////// AD STRUCT //////////////
////////////////////////////////////////

// Reading root AD dirs (ou).
func ReadRootGroups(userName, passWord, host string, port interface{},
	baseDn string, useTls, openLdap bool) ([]GroupInfo, error) {

	res := make([]GroupInfo, 0)

	conn, err := NewLdapConn(userName, passWord, host, port, useTls)
	if err != nil {
		logging.Logger.Error(err)
		return res, err
	}
	defer func() { conn.Close() }()

	var attributes = make([]string, 0)
	if openLdap {
		attributes = []string{"ou"}
	} else {
		attributes = []string{"name", "ou", "distinguishedName"}
	}

	searchRequest := ldap.NewSearchRequest(
		baseDn,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		FilterGroup,
		attributes,
		nil,
	)

	searchResult, err := conn.Connection.Search(searchRequest)
	if err != nil {
		logging.Logger.Error(err)
		return res, errorCustom.GlobalErrors.ErrBadData()
	}

	for _, entry := range searchResult.Entries {
		var inf GroupInfo

		inf.Ou = entry.GetAttributeValue("ou")

		if openLdap {
			inf.Name = inf.Ou
			inf.DName = entry.DN
		} else {
			inf.Name = entry.GetAttributeValue("name")
			inf.DName = entry.GetAttributeValue("distinguishedName")
		}

		res = append(res, inf)
	}

	return res, nil
}

// Reading AD subDirs in grp.
func ReadSubGroups(userName, passWord, grp string, level int, host string,
	port interface{}, useTls, openLdap bool) ([]GroupInfo, error) {

	res := make([]GroupInfo, 0)

	conn, err := NewLdapConn(userName, passWord, host, port, useTls)
	if err != nil {
		logging.Logger.Error(err)
		return res, err
	}
	defer func() { conn.Close() }()

	var attributes = make([]string, 0)
	if openLdap {
		attributes = []string{"ou"}
	} else {
		attributes = []string{"name", "ou", "distinguishedName"}
	}

	searchRequest := ldap.NewSearchRequest(
		grp,
		level, ldap.NeverDerefAliases, 0, 0, false,
		FilterGroup,
		attributes,
		nil,
	)

	searchResult, err := conn.Connection.Search(searchRequest)
	if err != nil {
		logging.Logger.Error(err)
		return res, errorCustom.GlobalErrors.ErrBadData()
	}

	for _, entry := range searchResult.Entries {
		var inf GroupInfo
		inf.Ou = entry.GetAttributeValue("ou")

		if openLdap {
			inf.Name = inf.Ou
			inf.DName = entry.DN
		} else {
			inf.Name = entry.GetAttributeValue("name")
			inf.DName = entry.GetAttributeValue("distinguishedName")
		}

		// Needed for recursive AD struct search
		inf.Has = make([]GroupInfo, 0)

		if strings.Contains(inf.DName, grp) && inf.DName != grp {
			res = append(res, inf)
		}
	}

	return res, nil
}

// Reading all users from grp.
func ReadGroupUsers(userName, passWord, grp, host string, port interface{}, useTls,
	openLdap bool) ([]ImportInfo, error) {

	res := make([]ImportInfo, 0)

	conn, err := NewLdapConn(userName, passWord, host, port, useTls)
	if err != nil {
		logging.Logger.Error(err)
		return res, err
	}
	defer func() { conn.Close() }()

	var filter string
	var attributes = make([]string, 0)
	if openLdap {
		filter = FilterUserLinux
		attributes = []string{"cn", "mail", "uid", "title", "departmentNumber"}
	} else {
		filter = FilterUserAd
		attributes = []string{"cn", "mail", "userPrincipalName", "title", "department"}
	}

	searchRequest := ldap.NewSearchRequest(
		grp,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil,
	)

	searchResult, err := conn.Connection.Search(searchRequest)
	if err != nil {
		logging.Logger.Warning(err)
	}

	if searchResult != nil {
		for _, entry := range searchResult.Entries {

			var inf ImportInfo

			inf.Name = entry.GetAttributeValue("cn")
			inf.Mail = entry.GetAttributeValue("mail")
			inf.Title = entry.GetAttributeValue("title")

			if openLdap {
				inf.Login = entry.GetAttributeValue("uid")
				inf.Department = entry.GetAttributeValue("departmentNumber")
			} else {
				inf.Login = entry.GetAttributeValue("userPrincipalName")
				inf.Department = entry.GetAttributeValue("department")
			}

			// for no Name users cases
			if inf.Name == nil {
				inf.Name = "NoName"
			}

			res = append(res, inf)
		}
	}

	return res, nil
}

func RecursiveADSearch(prevLevel *[]GroupInfo, userName, passWord, host string, port interface{}, useTls, openLdap bool,
	level int) *[]GroupInfo {

	nextLevel := make([]GroupInfo, 0)
	for k, v := range *prevLevel {
		nextLevel, _ := ReadSubGroups(userName, passWord, v.DName, ldap.ScopeSingleLevel, host, port, useTls, openLdap)
		if nextLevel != nil {
			if level < DepthOfLdapSearch {
				RecursiveADSearch(&nextLevel, userName, passWord, host, port, useTls, openLdap, level+1)
			}
			(*prevLevel)[k].Has = nextLevel
		}
	}
	return &nextLevel
}

// Reading full AD structure.
func ReadAdStruct(userName, passWord, host string, port interface{},
	baseDn string, useTls, openLdap bool) (ADStruct, error) {
	var res ADStruct

	firstLevel, err := ReadRootGroups(userName, passWord, host, port, baseDn, useTls, openLdap)
	if err != nil {
		logging.Logger.Error(err)
		return ADStruct{}, err
	}

	if firstLevel != nil {
		_ = RecursiveADSearch(&firstLevel, userName, passWord, host, port, useTls, openLdap, 2)
		res.AD = firstLevel
	}

	return res, nil
}
