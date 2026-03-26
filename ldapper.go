// Copyright 2020-2024 NGR Softlab
package ldapper

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// TODO: make 3.0 version with united methods (united tls config logic)

////////////////////////////////////////////// LdapConn struct

type LdapConnOptions struct {
	OpenLDAP bool
}

type LdapConn struct {
	host       string
	port       interface{}
	user       string
	password   string
	useTLS     bool
	options    LdapConnOptions
	Connection *ldap.Conn
}

// NewLdapConn - create new conn (with InsecureSkipVerify: true)
func NewLdapConn(userName, passWord,
	host string, port interface{},
	useTls bool, options ...LdapConnOptions) (*LdapConn, error) {

	var uri string
	var conn *ldap.Conn
	var err error
	uri = fmt.Sprintf("ldap://%s:%v", host, port)

	if useTls {
		uri = fmt.Sprintf("ldaps://%s:%v", host, port)
		conn, err = ldap.DialURL(uri, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	} else {
		conn, err = ldap.DialURL(uri)
	}
	if err != nil {
		return nil, fmt.Errorf("bad host/post params error: %s", err.Error())
	}

	err = conn.Bind(userName, passWord)
	if err != nil {
		return nil, fmt.Errorf("bad credential params error: %s", err.Error())
	}

	var connOptions LdapConnOptions
	if len(options) > 0 {
		// set only 1st options object
		connOptions = options[0]
	}

	return &LdapConn{
		host:       host,
		port:       port,
		user:       userName,
		password:   passWord,
		useTLS:     useTls,
		options:    connOptions,
		Connection: conn,
	}, nil
}

// NewLdapConnWithTLSConfig - create new conn with passed tls config
func NewLdapConnWithTLSConfig(userName, passWord,
	host string, port interface{},
	tlsCfg *tls.Config, options ...LdapConnOptions) (*LdapConn, error) {

	var uri string
	var conn *ldap.Conn
	var err error
	uri = fmt.Sprintf("ldap://%s:%v", host, port)

	if tlsCfg == nil {
		return nil, fmt.Errorf("passed nil tls config")
	}

	uri = fmt.Sprintf("ldaps://%s:%v", host, port)
	conn, err = ldap.DialURL(uri, ldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return nil, fmt.Errorf("bad host/post params error: %s", err.Error())
	}

	err = conn.Bind(userName, passWord)
	if err != nil {
		return nil, fmt.Errorf("bad credential params error: %s", err.Error())
	}

	var connOptions LdapConnOptions
	if len(options) > 0 {
		// set only 1st options object
		connOptions = options[0]
	}

	return &LdapConn{
		host:       host,
		port:       port,
		user:       userName,
		password:   passWord,
		useTLS:     true,
		options:    connOptions,
		Connection: conn,
	}, nil
}

func (conn *LdapConn) Close() {
	if conn.Connection != nil {
		err := conn.Connection.Close()
		if err != nil {
			return
		}
	}
}

////////////////////////////////////////////// Conn tests

// TryAccess Test auth in AD (conn with InsecureSkipVerify: true)
func TryAccess(userName, passWord,
	host string, port interface{},
	useTls bool) error {

	_, err := NewLdapConn(userName, passWord, host, port, useTls)

	return err
}

// TryAccessWithTLSConfig Test auth in AD with passed tls config
func TryAccessWithTLSConfig(userName, passWord,
	host string, port interface{},
	tlsCfg *tls.Config) error {

	_, err := NewLdapConnWithTLSConfig(userName, passWord, host, port, tlsCfg)

	return err
}

// TestBaseDn Test search in AD baseDn path (conn with InsecureSkipVerify: true)
func TestBaseDn(userName, passWord,
	host string, port interface{},
	baseDn string, useTls, openLdap bool) error {

	conn, err := NewLdapConn(userName, passWord, host, port, useTls, LdapConnOptions{OpenLDAP: openLdap})
	if err != nil {
		return err
	}
	defer func() { conn.Close() }()

	filter := filterGroup

	searchRequest := ldap.NewSearchRequest(
		baseDn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		testBaseDNAttr,
		nil,
	)

	searchResult, err := conn.Connection.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("bad base_dn param: %s", err.Error())
	}

	var cn interface{}
	for _, entry := range searchResult.Entries {
		cn = entry.GetAttributeValue("cn")
		break
	}

	if cn == nil {
		return fmt.Errorf("bad base_dn param: no cn")
	}

	return nil
}

// TestBaseDnWithTLSConfig Test search in AD baseDn path with passed tls config
func TestBaseDnWithTLSConfig(userName, passWord,
	host string, port interface{},
	baseDn string, tlsCfg *tls.Config, openLdap bool) error {

	conn, err := NewLdapConnWithTLSConfig(userName, passWord, host, port, tlsCfg, LdapConnOptions{OpenLDAP: openLdap})
	if err != nil {
		return err
	}
	defer func() { conn.Close() }()

	filter := filterGroup

	searchRequest := ldap.NewSearchRequest(
		baseDn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		testBaseDNAttr,
		nil,
	)

	searchResult, err := conn.Connection.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("bad base_dn param: %s", err.Error())
	}

	var cn interface{}
	for _, entry := range searchResult.Entries {
		cn = entry.GetAttributeValue("cn")
		break
	}

	if cn == nil {
		return fmt.Errorf("bad base_dn param: no cn")
	}

	return nil
}

////////////////////////////////////////////// Get info methods

// ReadUserInfo Reading user info from AD (conn with InsecureSkipVerify: true)
func ReadUserInfo(userName, domUser, domPassWord,
	host string, port interface{},
	baseDn string, useTls, openLdap bool) (UserInfo, error) {

	var inf UserInfo

	conn, err := NewLdapConn(domUser, domPassWord, host, port, useTls)
	if err != nil {
		return inf, err
	}
	defer func() { conn.Close() }()

	var filter string
	var attributes = make([]string, 0)

	if openLdap {
		filter = fmt.Sprintf(searchFilterUserOpenLDAP, userName)
		attributes = []string{"cn", "departmentNumber", "mobile", "mail", "title", "jpegPhoto"}
	} else {
		filter = fmt.Sprintf(searchFilterUserAD, userName)
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

// ReadUserInfoWithTLSConfig Reading user info from AD with passed tls config
func ReadUserInfoWithTLSConfig(userName, domUser, domPassWord,
	host string, port interface{},
	baseDn string, tlsCfg *tls.Config, openLdap bool) (UserInfo, error) {

	var inf UserInfo

	conn, err := NewLdapConnWithTLSConfig(domUser, domPassWord, host, port, tlsCfg)
	if err != nil {
		return inf, err
	}
	defer func() { conn.Close() }()

	var filter string
	var attributes = make([]string, 0)

	if openLdap {
		filter = fmt.Sprintf(searchFilterUserOpenLDAP, userName)
		attributes = []string{"cn", "departmentNumber", "mobile", "mail", "title", "jpegPhoto"}
	} else {
		filter = fmt.Sprintf(searchFilterUserAD, userName)
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

////////////////////////////////////////////// Get struct methods

// ReadRootGroups Reading root AD dirs (ou) (conn with InsecureSkipVerify: true)
func ReadRootGroups(userName, passWord,
	host string, port interface{},
	baseDn string, useTls, openLdap bool) ([]GroupInfo, error) {

	res := make([]GroupInfo, 0)

	conn, err := NewLdapConn(userName, passWord, host, port, useTls)
	if err != nil {
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
		filterGroup,
		attributes,
		nil,
	)

	searchResult, err := conn.Connection.Search(searchRequest)
	if err != nil {
		return res, fmt.Errorf("bad search: %s", err.Error())
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

// ReadRootGroupsWithTLSConfig Reading root AD dirs (ou) with passed tls config
func ReadRootGroupsWithTLSConfig(userName, passWord,
	host string, port interface{},
	baseDn string, tlsCfg *tls.Config, openLdap bool) ([]GroupInfo, error) {

	res := make([]GroupInfo, 0)

	conn, err := NewLdapConnWithTLSConfig(userName, passWord, host, port, tlsCfg)
	if err != nil {
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
		filterGroup,
		attributes,
		nil,
	)

	searchResult, err := conn.Connection.Search(searchRequest)
	if err != nil {
		return res, fmt.Errorf("bad search: %s", err.Error())
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

// ReadSubGroups Reading AD subDirs in group (conn with InsecureSkipVerify: true)
func ReadSubGroups(userName, passWord, grp string,
	level int, host string, port interface{},
	useTls, openLdap bool) ([]GroupInfo, error) {

	res := make([]GroupInfo, 0)

	conn, err := NewLdapConn(userName, passWord, host, port, useTls)
	if err != nil {
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
		filterGroup,
		attributes,
		nil,
	)

	searchResult, err := conn.Connection.Search(searchRequest)
	if err != nil {
		return res, fmt.Errorf("bad search: %s", err.Error())
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

// ReadSubGroupsWithTLSConfig Reading AD subDirs in group with tls config
func ReadSubGroupsWithTLSConfig(userName, passWord, grp string,
	level int, host string, port interface{},
	tlsCfg *tls.Config, openLdap bool) ([]GroupInfo, error) {

	res := make([]GroupInfo, 0)

	conn, err := NewLdapConnWithTLSConfig(userName, passWord, host, port, tlsCfg)
	if err != nil {
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
		filterGroup,
		attributes,
		nil,
	)

	searchResult, err := conn.Connection.Search(searchRequest)
	if err != nil {
		return res, fmt.Errorf("bad search: %s", err.Error())
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

// ReadGroupUsers Reading all users from group (conn with InsecureSkipVerify: true)
func ReadGroupUsers(userName, passWord, grp,
	host string, port interface{},
	useTls, openLdap bool) ([]ImportInfo, error) {

	res := make([]ImportInfo, 0)

	conn, err := NewLdapConn(userName, passWord, host, port, useTls)
	if err != nil {
		return res, err
	}
	defer func() { conn.Close() }()

	var filter string
	var attributes = make([]string, 0)
	if openLdap {
		filter = filterUserOpenLDAP
		attributes = []string{"cn", "mail", "uid", "title", "departmentNumber"}
	} else {
		filter = filterUserAD
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

// ReadGroupUsersWithTLSConfig Reading all users from group with passed tls config
func ReadGroupUsersWithTLSConfig(userName, passWord, grp,
	host string, port interface{},
	tlsCfg *tls.Config, openLdap bool) ([]ImportInfo, error) {

	res := make([]ImportInfo, 0)

	conn, err := NewLdapConnWithTLSConfig(userName, passWord, host, port, tlsCfg)
	if err != nil {
		return res, err
	}
	defer func() { conn.Close() }()

	var filter string
	var attributes = make([]string, 0)
	if openLdap {
		filter = filterUserOpenLDAP
		attributes = []string{"cn", "mail", "uid", "title", "departmentNumber"}
	} else {
		filter = filterUserAD
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

// RecursiveADSearch - run recursive search in AD (group->subgroup->etc.) (conn with InsecureSkipVerify: true)
func RecursiveADSearch(prevLevel *[]GroupInfo,
	userName, passWord,
	host string, port interface{},
	useTls, openLdap bool,
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

// RecursiveADSearchWithTLSConfig - run recursive search in AD (group->subgroup->etc.) with passed tls config
func RecursiveADSearchWithTLSConfig(prevLevel *[]GroupInfo,
	userName, passWord,
	host string, port interface{},
	tlsCfg *tls.Config, openLdap bool,
	level int) *[]GroupInfo {

	nextLevel := make([]GroupInfo, 0)
	for k, v := range *prevLevel {
		nextLevel, _ := ReadSubGroupsWithTLSConfig(userName, passWord, v.DName, ldap.ScopeSingleLevel, host, port, tlsCfg, openLdap)
		if nextLevel != nil {
			if level < DepthOfLdapSearch {
				RecursiveADSearchWithTLSConfig(&nextLevel, userName, passWord, host, port, tlsCfg, openLdap, level+1)
			}
			(*prevLevel)[k].Has = nextLevel
		}
	}
	return &nextLevel
}

// ReadAdStruct Reading full AD structure (with depth 2) (conn with InsecureSkipVerify: true)
func ReadAdStruct(userName, passWord, host string, port interface{},
	baseDn string, useTls, openLdap bool) (ADStruct, error) {
	var res ADStruct

	firstLevel, err := ReadRootGroups(userName, passWord, host, port, baseDn, useTls, openLdap)
	if err != nil {
		return ADStruct{}, err
	}

	if firstLevel != nil {
		_ = RecursiveADSearch(&firstLevel, userName, passWord, host, port, useTls, openLdap, 2)
		res.AD = firstLevel
	}

	return res, nil
}

// ReadAdStructWithTLSConfig Reading full AD structure (with depth 2) with passed tls config
func ReadAdStructWithTLSConfig(userName, passWord, host string, port interface{},
	baseDn string, tlsCfg *tls.Config, openLdap bool) (ADStruct, error) {
	var res ADStruct

	firstLevel, err := ReadRootGroupsWithTLSConfig(userName, passWord, host, port, baseDn, tlsCfg, openLdap)
	if err != nil {
		return ADStruct{}, err
	}

	if firstLevel != nil {
		_ = RecursiveADSearchWithTLSConfig(&firstLevel, userName, passWord, host, port, tlsCfg, openLdap, 2)
		res.AD = firstLevel
	}

	return res, nil
}
