package ldap

import (
	"crypto/tls"
	"io/ioutil"
	"sync"

	"github.com/go-ldap/ldap/v3"
	"github.com/pkg/errors"
)

var lock = &sync.Mutex{}
var ldapConn *ldap.Conn

type ObjectType int

const (
	Users ObjectType = iota
	Groups
)

type RawLdapData struct {
	DN            string
	Attributes    map[string]string
	RawAttributes map[string][][]byte
}

func Open(cfg *Config) (*ldap.Conn, error) {
	var tlsConfig *tls.Config

	if cfg.LdapCertConn {

		certPlain, err := os.ReadFile(cfg.LdapTlsCert)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to load the certificate")

		}

		key, err := os.ReadFile(cfg.LdapTlsKey)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to load the key")
		}

		certX509, err := tls.X509KeyPair(certPlain, key)
		if err != nil {
			return nil, errors.WithMessage(err, "failed X509")

		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{certX509}}

	} else {

		tlsConfig = &tls.Config{InsecureSkipVerify: !cfg.CertValidation}
	}

	lock.Lock()
	defer lock.Unlock()

	if ldapConn == nil {
		conn, err := ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(tlsConfig))
		if err != nil {
			return nil, errors.Wrap(err, "failed to connect to LDAP")
		}
		ldapConn = conn
		if cfg.StartTLS {
			// Reconnect with TLS
			err := ldapConn.StartTLS(tlsConfig)
			if err != nil {
				ldapConn.Close()
				ldapConn = nil
				return nil, errors.Wrap(err, "failed to star TLS on connection")
			}
		}

		err = ldapConn.Bind(cfg.BindUser, cfg.BindPass)
		if err != nil {
			ldapConn.Close()
			ldapConn = nil
			return nil, errors.Wrap(err, "failed to bind to LDAP")
		}
	}

	return ldapConn, nil
}

func Close() {
	if ldapConn != nil {
		ldapConn.Close()
	}
	ldapConn = nil
}

func FindAllObjects(cfg *Config, objType ObjectType) ([]RawLdapData, error) {
	var sr *ldap.SearchResult
	var err error
	var client *ldap.Conn

	client, err = Open(cfg)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to open ldap connection")
	}
	defer Close(client)

	var searchRequest *ldap.SearchRequest
	var attrs []string

	switch objType {
	case Users:
		// Search all users
		attrs = []string{"dn", cfg.EmailAttribute, cfg.EmailAttribute, cfg.FirstNameAttribute, cfg.LastNameAttribute,
			cfg.PhoneAttribute, cfg.GroupMemberAttribute}
		searchRequest = ldap.NewSearchRequest(
			cfg.BaseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			cfg.SyncFilter, attrs, nil,
		)
	case Groups:
		if cfg.SyncGroupFilter == "" {
			return nil, nil // no groups
		}
		// Search all groups
		attrs = []string{"dn", cfg.GroupMemberAttribute}
		searchRequest = ldap.NewSearchRequest(
			cfg.BaseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			cfg.SyncGroupFilter, attrs, nil,
		)
	default:
		panic("invalid object type")
	}

	sr, err = client.SearchWithPaging(searchRequest, 100)
	if err != nil {
		// try to close and re-open the connection
		Close()
		client, err = Open(cfg)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to open ldap connection")
		}
		sr, err = client.SearchWithPaging(searchRequest, 100)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to search in ldap")
		}
	}

	tmpData := make([]RawLdapData, 0, len(sr.Entries))

	for _, entry := range sr.Entries {
		tmp := RawLdapData{
			DN:            entry.DN,
			Attributes:    make(map[string]string, len(attrs)),
			RawAttributes: make(map[string][][]byte, len(attrs)),
		}

		for _, field := range attrs {
			tmp.Attributes[field] = entry.GetAttributeValue(field)
			tmp.RawAttributes[field] = entry.GetRawAttributeValues(field)
		}

		tmpData = append(tmpData, tmp)
	}

	return tmpData, nil
}
