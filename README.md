# ngr-ldapper
Lib for working with ldap

# import

```
import (
    ldapper "github.com/NGRsoftlab/ngr-ldapper/v2"
)
```

or (if you want v1)

```
import (
    ldapCommon "github.com/NGRsoftlab/ngr-ldapper"
)
```

# example v2 (new, get struct, get userInfo)
```
// create new ldap connection
conn, err := NewLdapConn(user, password,host, port,
				useTLS, LdapConnOptions{openLDAP: tt.params.openLDAP})
if err != nil {
	return err
}	
defer func() { conn.Close() }()

ADStruct, err := conn.GetStruct(baseDN)
if err != nil {
	return err
}	
fmt.Println(ADStruct)	

userInfo, err := conn.GetUserInfo(userToFind, baseDN)
if err != nil {
	return err
}	
fmt.Println(userInfo)		

// etc. other operations without opening new conn every time	
```


# example v1 (old, get struct, get userInfo)
```
// open-close new conn is inside
ADStruct, err := ReadAdStruct(user, password,
				host, port,
				baseDN, useTLS, openLDAP)
if err != nil {
	return err
}	
fmt.Println(ADStruct)

// open-close new conn is inside
userInfo, err := ReadUserInfo(user, userToFind, password,
				host, port,
				baseDN, useTLS, openLDAP)
if err != nil {
	return err
}	
fmt.Println(userInfo)
```