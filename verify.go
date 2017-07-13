/* -.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.

* File Name : verify.go

* Purpose :

* Creation Date : 12-16-2014

* Last Modified : Wed Jul 12 18:31:12 2017

* Created By : Kiyor

_._._._._._._._._._._._._._._._._._._._._.*/

package chkcert

import (
	"fmt"
	"github.com/kiyor/golib"
	"strings"
	"time"
)

var (
	OpensslPath      = "/usr/bin/openssl"
	chkCertCmd       = "${openssl} x509 -text -noout"
	chkCertCmdShort  = "${openssl} x509 -noout"
	chkPrivKeyCmd    = "${openssl} rsa -check"
	chkCertMd5Cmd    = "${openssl} x509 -noout -modulus | ${openssl} md5"
	chkPrivKeyMd5Cmd = "${openssl} rsa -noout -modulus | ${openssl} md5"
)

func initCmd(cmd, src string) string {
	if len(src) > 11 && src[:11] == "-----BEGIN " {
		return fmt.Sprintf("openssl='%s';echo '%s' | %s", OpensslPath, src, cmd)
	} else {
		return fmt.Sprintf("openssl='%s';cat '%s' | %s", OpensslPath, src, cmd)
	}

}

func ChkCert(src string) (string, error) {
	cmd := initCmd(chkCertCmd, src)
	return golib.Osexec(cmd)
}
func ChkPrivKey(src string) (string, error) {
	cmd := initCmd(chkPrivKeyCmd, src)
	out, err := golib.Osexec(cmd)
	if err != nil && err.Error() == "writing RSA key" {
		err = nil
	}
	return out, err
}
func ChkCertMd5(src string) (string, error) {
	cmd := initCmd(chkCertMd5Cmd, src)
	out, err := golib.Osexec(cmd)
	if len(out) > 9 {
		out = out[9:]
	}
	return out, err
}
func ChkPrivKeyMd5(src string) (string, error) {
	cmd := initCmd(chkPrivKeyMd5Cmd, src)
	out, err := golib.Osexec(cmd)
	if len(out) > 9 {
		out = out[9:]
	}
	return out, err
}

func ChkCertTime(src string) (before, after time.Time) {
	cmd := initCmd(chkCertCmd, src)
	cmd += " | grep -oP '(?<=Not Before: ).*'"
	b, _ := golib.Osexec(cmd)
	b = strings.Replace(b, "  ", " 0", -1)
	before, _ = time.Parse(certTimeFormat, b)

	cmd = initCmd(chkCertCmd, src)
	cmd += " | grep -oP '(?<=Not After : ).*'"
	a, _ := golib.Osexec(cmd)
	a = strings.Replace(a, "  ", " 0", -1)
	after, _ = time.Parse(certTimeFormat, a)

	return
}

func ChkCertIssuer(src string) string {
	return chkCertInfo(src, "issuer")
}
func ChkCertSubject(src string) string {
	return chkCertInfo(src, "subject")
}

func chkCertInfo(src, attr string) (info string) {
	cmd := initCmd(chkCertCmdShort, src)
	cmd += " -" + attr
	info, _ = golib.Osexec(cmd)
	if len(info) > len(attr)+2 {
		info = info[len(attr)+2:]
	}
	return
}

func ChkCertDNS(src string) []string {
	cmd := initCmd(chkCertCmd, src)
	cmd += " | grep DNS:"
	out, _ := golib.Osexec(cmd)
	for strings.Contains(out, " ") {
		out = strings.Replace(out, " ", "", -1)
	}
	dns := strings.Split(out, ",")
	var res []string
	for _, v := range dns {
		res = append(res, strings.ToLower(v[4:]))
	}

	return res
}
