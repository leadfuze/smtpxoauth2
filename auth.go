package smtpxoauth2

import (
	"errors"
	"fmt"
	"net/smtp"
)

type xoauth2Auth struct {
	user, accessToken string
	host              string
}

// New returns a smtp.Auth that implements the XOAUTH2 authentication mechanism
func New(user, accessToken, host string) smtp.Auth {
	return &xoauth2Auth{user, accessToken, host}
}

func (a *xoauth2Auth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		advertised := false
		for _, mechanism := range server.Auth {
			if mechanism == "XOAUTH2" {
				advertised = true
				break
			}
		}
		if !advertised {
			return "", nil, errors.New("XOAUTH2 not advertised by server")
		}
	}
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	resp := []byte(fmt.Sprint("user=", a.user, "\001auth=Bearer ", a.accessToken, "\001\001"))
	return "XOAUTH2", resp, nil
}

func (a *xoauth2Auth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		// We've already sent everything.
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}
