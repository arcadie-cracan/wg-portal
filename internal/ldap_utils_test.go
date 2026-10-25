package internal

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"

	"github.com/h44z/wg-portal/internal/config"
)

func TestLdapConvertEntries_UserIdentifierFallback(t *testing.T) {
	fields := &config.LdapFields{
		BaseFields:             config.BaseFields{UserIdentifier: "mail", Email: "mail"},
		UserIdentifierFallback: "userPrincipalName",
	}
	sr := &ldap.SearchResult{Entries: []*ldap.Entry{
		ldap.NewEntry("cn=a", map[string][]string{"mail": {"a@example.com"}, "userPrincipalName": {"x@example.com"}}),
		ldap.NewEntry("cn=b", map[string][]string{"userPrincipalName": {"B@Example.com"}}),
	}}

	users := LdapConvertEntries(sr, fields)

	assert.Equal(t, "a@example.com", LdapUserIdentifier(users[0], "mail"))
	assert.Equal(t, "b@example.com", LdapUserIdentifier(users[1], "mail"))
	assert.Equal(t, "", users[1]["mail"], "the email stays empty")
	assert.Contains(t, LdapSearchAttributes(fields), "userPrincipalName")
}
