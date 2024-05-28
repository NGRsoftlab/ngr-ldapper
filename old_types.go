// Copyright 2020-2024 NGR Softlab
package ldapper

// UserInfo User info from AD struct.
type UserInfo struct {
	CN         interface{} `json:"cn"` // full name
	Department interface{} `json:"department"`
	Mobile     interface{} `json:"mobile"`         // mobile phone
	Mail       interface{} `json:"mail"`           // email
	Title      interface{} `json:"title"`          // user title
	Photo      interface{} `json:"thumbnailPhoto"` // bad photo from AD

	Company interface{} `json:"company"`
	Address interface{} `json:"address"`
	City    interface{} `json:"city"`
	Index   interface{} `json:"index"`
	Country interface{} `json:"country"`
	Room    interface{} `json:"room"`
	Phone   interface{} `json:"phone"`
	Manager interface{} `json:"manager"`
}

// ImportInfo Short info for showing.
type ImportInfo struct {
	Name       interface{} `json:"name"` // full name (= cn)
	Login      interface{} `json:"login"`
	Mail       interface{} `json:"mail"`
	Title      interface{} `json:"title"`
	Department interface{} `json:"department"`
}
