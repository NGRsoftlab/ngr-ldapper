// Copyright 2020-2024 NGR Softlab
package ldapper

////////////////////////////////////////////// Constants

const (
	// searchFilterUserAD User search AD pattern
	searchFilterUserAD = "(userPrincipalName=%s*)"

	// searchFilterUserOpenLDAP User search openLdap pattern
	searchFilterUserOpenLDAP = "(|(&(objectClass=person)(cn=%s))(structuralObjectClass=organizationalRole))"

	// filterGroup department pattern
	filterGroup = "(&(objectClass=organizationalUnit))"

	// filterUserAD, FilterUserLinux user obj in ou pattern
	filterUserAD       = "(&(objectClass=User))"
	filterUserOpenLDAP = "(&(objectClass=person))"

	// DepthOfLdapSearch For get AD struct
	DepthOfLdapSearch = 4
)

////////////////////////////////////////////// Attr templates

var (
	testBaseDNAttr = []string{"cn"}

	openLDAPUserAttrs = []string{"cn", "departmentNumber", "mobile", "mail", "title", "jpegPhoto"}
	ADUserAttrs       = []string{
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

	openLDAPGroupUserAttrs = []string{"cn", "departmentNumber", "mail", "uid", "title"}
	ADGroupUserAttrs       = []string{"cn", "mail", "userPrincipalName", "title", "department"}

	openLDAPGroupAttrs = []string{"ou"}
	ADGroupAttrs       = []string{"name", "ou", "distinguishedName"}
)
