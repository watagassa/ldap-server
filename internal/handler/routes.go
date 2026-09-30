// Package handler は LDAP の各オペレーションに対するハンドラーを提供する
package handler

import (
	ldap "github.com/vjeantet/ldapserver"
)

// NewRouteMux は Bind / Extended(WhoAmI) / Search のハンドラーを登録したルーターを返す
func NewRouteMux() *ldap.RouteMux {
	routes := ldap.NewRouteMux()
	routes.Bind(handleSimpleBind).AuthenticationChoice("simple")
	routes.Extended(handleWhoAmI).RequestName(ldap.NoticeOfWhoAmI).Label("Ext - WhoAmI")
	routes.Search(handleSearch)
	return routes
}
