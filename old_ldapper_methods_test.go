// Copyright 2020-2024 NGR Softlab
package ldapper

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/*
	This is only smth like test template (error on conn creating without real params)
	To check real work - you need to put real params into test case (ip, port, user, pass, etc.)
*/

func TestReadUserInfo(t *testing.T) {
	type ConnParams struct {
		host     string
		port     interface{}
		user     string
		domUser  string
		password string
		useTLS   bool
		openLDAP bool
		baseDN   string
	}

	tests := []struct {
		name      string
		params    ConnParams
		mustFail  bool
		failError error
	}{
		{
			name: "invalid notls",
			params: ConnParams{
				host:     "test.ru",
				port:     389,
				user:     "test",
				password: "test",
				useTLS:   false,
			},
			mustFail:  true,
			failError: fmt.Errorf("bad host/post params error: LDAP Result Code 200 \"Network Error\": dial tcp: lookup test.ru: no such host"),
		},
		{
			name: "invalid tls",
			params: ConnParams{
				host:     "test.ru",
				port:     636,
				user:     "test",
				password: "test",
				useTLS:   true,
			},
			mustFail:  true,
			failError: fmt.Errorf("bad host/post params error: LDAP Result Code 200 \"Network Error\": dial tcp: lookup test.ru: no such host"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadUserInfo(tt.params.user, tt.params.domUser, tt.params.password,
				tt.params.host, tt.params.port,
				tt.params.baseDN, tt.params.useTLS, tt.params.openLDAP)
			if tt.mustFail {
				require.Error(t, err)
				assert.Equal(t, tt.failError.Error(), err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestReadRootGroups(t *testing.T) {
	type ConnParams struct {
		host     string
		port     interface{}
		user     string
		password string
		useTLS   bool
		openLDAP bool
		baseDN   string
	}

	tests := []struct {
		name      string
		params    ConnParams
		mustFail  bool
		failError error
	}{
		{
			name: "invalid notls",
			params: ConnParams{
				host:     "test.ru",
				port:     389,
				user:     "test",
				password: "test",
				useTLS:   false,
			},
			mustFail:  true,
			failError: fmt.Errorf("bad host/post params error: LDAP Result Code 200 \"Network Error\": dial tcp: lookup test.ru: no such host"),
		},
		{
			name: "invalid tls",
			params: ConnParams{
				host:     "test.ru",
				port:     636,
				user:     "test",
				password: "test",
				useTLS:   true,
			},
			mustFail:  true,
			failError: fmt.Errorf("bad host/post params error: LDAP Result Code 200 \"Network Error\": dial tcp: lookup test.ru: no such host"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadRootGroups(tt.params.user, tt.params.password,
				tt.params.host, tt.params.port,
				tt.params.baseDN, tt.params.useTLS, tt.params.openLDAP)
			if tt.mustFail {
				require.Error(t, err)
				assert.Equal(t, tt.failError.Error(), err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestReadSubGroups(t *testing.T) {
	type ConnParams struct {
		host     string
		port     interface{}
		user     string
		password string
		useTLS   bool
		openLDAP bool
		group    string
		level    int
	}

	tests := []struct {
		name      string
		params    ConnParams
		mustFail  bool
		failError error
	}{
		{
			name: "invalid notls",
			params: ConnParams{
				host:     "test.ru",
				port:     389,
				user:     "test",
				password: "test",
				useTLS:   false,
			},
			mustFail:  true,
			failError: fmt.Errorf("bad host/post params error: LDAP Result Code 200 \"Network Error\": dial tcp: lookup test.ru: no such host"),
		},
		{
			name: "invalid tls",
			params: ConnParams{
				host:     "test.ru",
				port:     636,
				user:     "test",
				password: "test",
				useTLS:   true,
			},
			mustFail:  true,
			failError: fmt.Errorf("bad host/post params error: LDAP Result Code 200 \"Network Error\": dial tcp: lookup test.ru: no such host"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadSubGroups(tt.params.user, tt.params.password, tt.params.group,
				tt.params.level, tt.params.host, tt.params.port,
				tt.params.useTLS, tt.params.openLDAP)
			if tt.mustFail {
				require.Error(t, err)
				assert.Equal(t, tt.failError.Error(), err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestReadGroupUsers(t *testing.T) {
	type ConnParams struct {
		host     string
		port     interface{}
		user     string
		password string
		useTLS   bool
		openLDAP bool
		group    string
	}

	tests := []struct {
		name      string
		params    ConnParams
		mustFail  bool
		failError error
	}{
		{
			name: "invalid notls",
			params: ConnParams{
				host:     "test.ru",
				port:     389,
				user:     "test",
				password: "test",
				useTLS:   false,
			},
			mustFail:  true,
			failError: fmt.Errorf("bad host/post params error: LDAP Result Code 200 \"Network Error\": dial tcp: lookup test.ru: no such host"),
		},
		{
			name: "invalid tls",
			params: ConnParams{
				host:     "test.ru",
				port:     636,
				user:     "test",
				password: "test",
				useTLS:   true,
			},
			mustFail:  true,
			failError: fmt.Errorf("bad host/post params error: LDAP Result Code 200 \"Network Error\": dial tcp: lookup test.ru: no such host"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadGroupUsers(tt.params.user, tt.params.password, tt.params.group,
				tt.params.host, tt.params.port,
				tt.params.useTLS, tt.params.openLDAP)
			if tt.mustFail {
				require.Error(t, err)
				assert.Equal(t, tt.failError.Error(), err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestReadAdStruct(t *testing.T) {
	type ConnParams struct {
		host     string
		port     interface{}
		user     string
		password string
		useTLS   bool
		openLDAP bool
		baseDN   string
	}

	tests := []struct {
		name      string
		params    ConnParams
		mustFail  bool
		failError error
	}{
		{
			name: "invalid notls",
			params: ConnParams{
				host:     "test.ru",
				port:     389,
				user:     "test",
				password: "test",
				useTLS:   false,
			},
			mustFail:  true,
			failError: fmt.Errorf("bad host/post params error: LDAP Result Code 200 \"Network Error\": dial tcp: lookup test.ru: no such host"),
		},
		{
			name: "invalid tls",
			params: ConnParams{
				host:     "test.ru",
				port:     636,
				user:     "test",
				password: "test",
				useTLS:   true,
			},
			mustFail:  true,
			failError: fmt.Errorf("bad host/post params error: LDAP Result Code 200 \"Network Error\": dial tcp: lookup test.ru: no such host"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadAdStruct(tt.params.user, tt.params.password,
				tt.params.host, tt.params.port,
				tt.params.baseDN, tt.params.useTLS, tt.params.openLDAP)
			if tt.mustFail {
				require.Error(t, err)
				assert.Equal(t, tt.failError.Error(), err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
