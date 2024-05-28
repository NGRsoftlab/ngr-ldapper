// Copyright 2020-2024 NGR Softlab
package ldapper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

/*
	This is only smth like test template (error on conn creating without real params)
	To check real work - you need to put real params into test case (ip, port, user, pass, etc.)
*/

func TestNewLdapConn(t *testing.T) {
	type ConnParams struct {
		host     string
		port     interface{}
		user     string
		password string
		useTLS   bool
	}

	tests := []struct {
		name     string
		params   ConnParams
		mustFail bool
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
			mustFail: true,
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
			mustFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := NewLdapConn(tt.params.user, tt.params.password,
				tt.params.host, tt.params.port,
				tt.params.useTLS)
			if tt.mustFail {
				require.Error(t, err)
			} else {
				defer func() { conn.Close() }()
				require.NoError(t, err)
			}
		})
	}
}

func TestTryAccess(t *testing.T) {
	type ConnParams struct {
		host     string
		port     interface{}
		user     string
		password string
		useTLS   bool
	}

	tests := []struct {
		name     string
		params   ConnParams
		mustFail bool
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
			mustFail: true,
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
			mustFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := TryAccess(tt.params.user, tt.params.password,
				tt.params.host, tt.params.port,
				tt.params.useTLS)
			if tt.mustFail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTestBaseDn(t *testing.T) {
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
		name     string
		params   ConnParams
		mustFail bool
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
			mustFail: true,
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
			mustFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := TestBaseDn(tt.params.user, tt.params.password,
				tt.params.host, tt.params.port,
				tt.params.baseDN, tt.params.useTLS, tt.params.openLDAP)
			if tt.mustFail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

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
		name     string
		params   ConnParams
		mustFail bool
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
			mustFail: true,
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
			mustFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadUserInfo(tt.params.user, tt.params.domUser, tt.params.password,
				tt.params.host, tt.params.port,
				tt.params.baseDN, tt.params.useTLS, tt.params.openLDAP)
			if tt.mustFail {
				require.Error(t, err)
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
		name     string
		params   ConnParams
		mustFail bool
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
			mustFail: true,
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
			mustFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadRootGroups(tt.params.user, tt.params.password,
				tt.params.host, tt.params.port,
				tt.params.baseDN, tt.params.useTLS, tt.params.openLDAP)
			if tt.mustFail {
				require.Error(t, err)
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
		name     string
		params   ConnParams
		mustFail bool
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
			mustFail: true,
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
			mustFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadSubGroups(tt.params.user, tt.params.password, tt.params.group,
				tt.params.level, tt.params.host, tt.params.port,
				tt.params.useTLS, tt.params.openLDAP)
			if tt.mustFail {
				require.Error(t, err)
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
		name     string
		params   ConnParams
		mustFail bool
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
			mustFail: true,
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
			mustFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadGroupUsers(tt.params.user, tt.params.password, tt.params.group,
				tt.params.host, tt.params.port,
				tt.params.useTLS, tt.params.openLDAP)
			if tt.mustFail {
				require.Error(t, err)
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
		name     string
		params   ConnParams
		mustFail bool
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
			mustFail: true,
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
			mustFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadAdStruct(tt.params.user, tt.params.password,
				tt.params.host, tt.params.port,
				tt.params.baseDN, tt.params.useTLS, tt.params.openLDAP)
			if tt.mustFail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
