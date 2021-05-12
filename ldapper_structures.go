package ldapper

const (
	// User search AD pattern
	SearchFilterUserAd = "(userPrincipalName=%s*)"
	// User search openLdap pattern
	SearchFilterUserLinux = "(|(&(objectClass=person)(cn=%s))(structuralObjectClass=organizationalRole))"
	// department pattern
	FilterGroup = "(&(objectClass=organizationalUnit))"
	// user obj in ou pattern
	FilterUserAd    = "(&(objectClass=User))"
	FilterUserLinux = "(&(objectClass=person))"
	// For get AD struct
	DepthOfLdapSearch = 4
)

/////////////////////////////////////////////

// User info from AD struct.
type UserInfo struct {
	CN         interface{} `json:"cn"` // full name
	Department interface{} `json:"department"`
	Mobile     interface{} `json:"mobile"`         // mobile phone
	Mail       interface{} `json:"mail"`           // email
	Title      interface{} `json:"title"`          // user title
	Photo      interface{} `json:"thumbnailPhoto"` // bad photo from AD

	Address interface{} `json:"address"`
	City    interface{} `json:"city"`
	Index   interface{} `json:"index"`
	Country interface{} `json:"country"`
	Room    interface{} `json:"room"`
	Phone   interface{} `json:"phone"`
	Manager interface{} `json:"manager"`
}

// Short info for showing.
type ImportInfo struct {
	Name       interface{} `json:"name"` // full name (= cn)
	Login      interface{} `json:"login"`
	Mail       interface{} `json:"mail"`
	Title      interface{} `json:"title"`
	Department interface{} `json:"department"`
}

// Department obj from AD struct.
type GroupInfo struct {
	Name  string      `json:"name"`
	DName string      `json:"distinguishedName"` // long department name
	Ou    string      `json:"ou"`
	Has   []GroupInfo `json:"has"` // list of subdirs (group children)
}

// Full AD struct.
type ADStruct struct {
	AD []GroupInfo `json:"ad_map"`
}
