// Copyright 2020 NGR Softlab
//
package ldapper

import "testing"

const (
	// TODO: set real creds for ok tests (be careful with flags (useTls & openLdap))
	okUser = "test"
	//okDomUser = "cn=admin,dc=example,dc=com" // openLdap
	okDomUser = "admin@example.com"
	okPsw     = "testtest"
	okHost    = "127.0.0.1"
	okPort    = 389
	okBaseDn  = "dc=example,dc=com"
)

/////////////////////////////////////////////////
func TestTryAccess(t *testing.T) {
	//t.Parallel()
	err := TryAccess(okDomUser, okPsw,
		okHost, okPort, false)
	if err != nil {
		t.Error(err)
	}
}

/////////////////////////////////////////////////
func TestReadUserInfo(t *testing.T) {
	//t.Parallel()
	res, err := ReadUserInfo(okUser, okDomUser, okPsw,
		okHost, okPort,
		okBaseDn,
		false, false)
	if err != nil {
		t.Error(err)
	}
	t.Log(res)
}

/////////////////////////////////////////////////
func TestTestBaseDn(t *testing.T) {
	//t.Parallel()
	err := TestBaseDn(okDomUser, okPsw,
		okHost, okPort,
		okBaseDn,
		false, false)
	if err != nil {
		t.Error(err)
	}
}

/////////////////////////////////////////////////
func TestReadRootGroups(t *testing.T) {
	res, err := ReadRootGroups(okDomUser, okPsw,
		okHost, okPort,
		okBaseDn,
		false, false)
	if err != nil {
		t.Error(err)
	}
	t.Log(res)
}

/////////////////////////////////////////////////
func TestReadAdStruct(t *testing.T) {
	res, err := ReadAdStruct(okDomUser, okPsw,
		okHost, okPort,
		okBaseDn,
		false, false)
	if err != nil {
		t.Error(err)
	}
	t.Log(res)
}
