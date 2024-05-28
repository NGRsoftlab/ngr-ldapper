// Copyright 2020-2024 NGR Softlab
package ldapper

// UserFullInfo User full info from AD struct
type UserFullInfo struct {
	CN         string `json:"cn"` // full name
	Department string `json:"department"`
	Mobile     string `json:"mobile"`         // mobile phone
	Mail       string `json:"mail"`           // email
	Title      string `json:"title"`          // user title
	Photo      string `json:"thumbnailPhoto"` // bad photo from AD

	Company string `json:"company"`
	Address string `json:"address"`
	City    string `json:"city"`
	Index   string `json:"index"`
	Country string `json:"country"`
	Room    string `json:"room"`
	Phone   string `json:"phone"`
	Manager string `json:"manager"`
}

// UserShortInfo Short info for showing somewhere in lists (light info list)
type UserShortInfo struct {
	Name       string `json:"name"` // full name (= cn)
	Login      string `json:"login"`
	Mail       string `json:"mail"`
	Title      string `json:"title"`
	Department string `json:"department"`
}

// GroupInfo Department obj from AD struct.
type GroupInfo struct {
	Name  string      `json:"name"`
	DName string      `json:"distinguishedName"` // long department name
	Ou    string      `json:"ou"`
	Has   []GroupInfo `json:"has"` // list of subdirs (group children)
}

// ADStruct Full AD struct.
type ADStruct struct {
	AD []GroupInfo `json:"ad_map"`
}
