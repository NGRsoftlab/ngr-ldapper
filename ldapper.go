// Copyright 2020-2024 NGR Softlab
package ldapper

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

////////////////////////////////////////////// LdapConn struct

type LdapConnOptions struct {
	openLDAP bool
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

func (conn *LdapConn) Close() {
	if conn.Connection != nil {
		err := conn.Connection.Close()
		if err != nil {
			return
		}
	}
}

////////////////////////////////////////////// Conn tests

// TryAccess Test auth in AD
func TryAccess(userName, passWord,
	host string, port interface{},
	useTls bool) error {

	_, err := NewLdapConn(userName, passWord, host, port, useTls)

	return err
}

// TestBaseDn Test search in AD baseDn path
func TestBaseDn(userName, passWord,
	host string, port interface{},
	baseDn string, useTls, openLdap bool) error {

	conn, err := NewLdapConn(userName, passWord, host, port, useTls, LdapConnOptions{openLDAP: openLdap})
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

func (conn *LdapConn) GetUserInfo(userName, baseDn string) (res UserFullInfo, err error) {
	var filter string
	var attributes = make([]string, 0)

	if conn.options.openLDAP {
		filter = fmt.Sprintf(searchFilterUserOpenLDAP, userName)
		attributes = openLDAPUserAttrs
	} else {
		filter = fmt.Sprintf(searchFilterUserAD, userName)
		attributes = ADUserAttrs
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
			res.CN = entry.GetAttributeValue("cn")
			res.Mobile = entry.GetAttributeValue("mobile")
			res.Mail = entry.GetAttributeValue("mail")
			res.Title = entry.GetAttributeValue("title")

			res.Manager = entry.GetAttributeValue("manager")
			res.Phone = entry.GetAttributeValue("telephoneNumber")
			res.Address = entry.GetAttributeValue("streetAddress")
			res.City = entry.GetAttributeValue("l")
			res.Room = entry.GetAttributeValue("physicalDeliveryOfficeName")
			res.Index = entry.GetAttributeValue("postalCode")
			res.Country = entry.GetAttributeValue("co")
			res.Company = entry.GetAttributeValue("company")

			if conn.options.openLDAP {
				res.Department = entry.GetAttributeValue("departmentNumber")
				res.Photo = entry.GetAttributeValue("jpegPhoto")
			} else {
				res.Department = entry.GetAttributeValue("department")
				res.Photo = entry.GetAttributeValue("thumbnailPhoto")
			}
		}
	}

	// for no Name users cases
	if res.CN == "" {
		res.CN = userName
	}

	return res, err
}

func (conn *LdapConn) GetGroupUsers(group string) (res []UserShortInfo, err error) {
	res = make([]UserShortInfo, 0)

	var filter string
	var attributes = make([]string, 0)
	if conn.options.openLDAP {
		filter = filterUserOpenLDAP
		attributes = openLDAPGroupUserAttrs
	} else {
		filter = filterUserAD
		attributes = ADGroupUserAttrs
	}

	searchRequest := ldap.NewSearchRequest(
		group,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil,
	)

	searchResult, err := conn.Connection.Search(searchRequest)

	if searchResult != nil {
		for _, entry := range searchResult.Entries {

			var inf UserShortInfo

			inf.Name = entry.GetAttributeValue("cn")
			inf.Mail = entry.GetAttributeValue("mail")
			inf.Title = entry.GetAttributeValue("title")

			if conn.options.openLDAP {
				inf.Login = entry.GetAttributeValue("uid")
				inf.Department = entry.GetAttributeValue("departmentNumber")
			} else {
				inf.Login = entry.GetAttributeValue("userPrincipalName")
				inf.Department = entry.GetAttributeValue("department")
			}

			// for no Name users cases
			if inf.Name == "" {
				inf.Name = "NoName"
			}

			res = append(res, inf)
		}
	}

	return res, err
}

////////////////////////////////////////////// Get struct methods

// GetStruct Reading full AD structure (with depth 2)
func (conn *LdapConn) GetStruct(baseDn string) (res ADStruct, err error) {
	firstLevel, err := conn.GetRootGroups(baseDn)
	if err != nil {
		return ADStruct{}, err
	}

	if firstLevel != nil {
		_ = conn.GetRecursiveSearchResult(&firstLevel, 2)
		res.AD = firstLevel
	}

	return res, nil
}

// GetRecursiveSearchResult - run recursive search in AD (group->subgroup->etc.), return groups tree info
func (conn *LdapConn) GetRecursiveSearchResult(prevLevel *[]GroupInfo, level int) *[]GroupInfo {
	nextLevel := make([]GroupInfo, 0)
	for k, v := range *prevLevel {
		nextLevel, _ := conn.GetSubGroups(v.DName, ldap.ScopeSingleLevel)
		if nextLevel != nil {
			if level < DepthOfLdapSearch {
				conn.GetRecursiveSearchResult(&nextLevel, level+1)
			}
			(*prevLevel)[k].Has = nextLevel
		}
	}
	return &nextLevel
}

// GetRootGroups Reading root AD folders (ou)
func (conn *LdapConn) GetRootGroups(baseDn string) (res []GroupInfo, err error) {
	res = make([]GroupInfo, 0)

	var attributes = make([]string, 0)
	if conn.options.openLDAP {
		attributes = openLDAPGroupAttrs
	} else {
		attributes = ADGroupAttrs
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

		if conn.options.openLDAP {
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

// GetSubGroups Reading AD subFolders in group
func (conn *LdapConn) GetSubGroups(group string, level int) (res []GroupInfo, err error) {
	res = make([]GroupInfo, 0)

	var attributes = make([]string, 0)
	if conn.options.openLDAP {
		attributes = openLDAPGroupAttrs
	} else {
		attributes = ADGroupAttrs
	}

	searchRequest := ldap.NewSearchRequest(
		group,
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

		if conn.options.openLDAP {
			inf.Name = inf.Ou
			inf.DName = entry.DN
		} else {
			inf.Name = entry.GetAttributeValue("name")
			inf.DName = entry.GetAttributeValue("distinguishedName")
		}

		// Needed for recursive AD struct search
		inf.Has = make([]GroupInfo, 0)

		if strings.Contains(inf.DName, group) && inf.DName != group {
			res = append(res, inf)
		}
	}

	return res, nil
}
