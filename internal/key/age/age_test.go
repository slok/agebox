package age_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/slok/agebox/internal/key/age"
	"github.com/slok/agebox/internal/log"
)

func TestKeyFactoryPublicKey(t *testing.T) {
	tests := map[string]struct {
		key    string
		expErr bool
	}{
		"Empty key should error.": {
			key:    "",
			expErr: true,
		},

		"Invalid key should error.": {
			key:    "---",
			expErr: true,
		},

		"RSA keys should be valid.": {
			key:    `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDHUiV702xSuXpa7pLwewUUgbxiBdgpeyLCjN5MlQ2RW8J99TAKAjKOVTMoFoAmeTqy7hKSvmHOsMMQgolgm+s7zOlwyupvMahZ/qCKXowtjwmiZ6PLGmkDaNdfiTOvEJICrh3fv87U2zpueBb17TtvLebcchQmlOlr4hcwZCIrORiUlSKxes6OqC1ctVksCn1ZtogBKCXhk0iRedm0Pv2mPM6a4ZMNGkAosoSxpph+z6Lh1KAenA7pS2RQnvcQzPfzCS8jleb43Zn9F2AqGbvnBKxLzRciq8S6sDPpNwOy1ZrP1meWxYbT6zTjI6CbMZmNxADRmpz9SwgcvqTATtfSa0GJgjrLA4xs74mnXO5T5J8J2BL+KOTW94PQ5UHGSjQkzuZmcpLV80q4GQUQJaPU5xbO39hhiaF9vd2sR0AXl2pEqu22trEKXvbct6VY9Iuc50DEbMTcDwW/u8L6Hzpe03vIdhjjk0/Gw77+2JXebkIIVzwliesiEnYeUFCZUVE=`,
			expErr: false,
		},

		"Ed25519 keys should be valid.": {
			key:    `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP54CpoL6zV+qBKp2l/Dfx1iX7X0kqjcv7OoD58jjZsy`,
			expErr: false,
		},

		"X25519 keys should be valid.": {
			key:    `age1dsnalzl92c076vh54s3xwqet87de2qde60gcfrpwnm9t3ghc6s7qadhjay`,
			expErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			f := age.NewFactory(nil, log.Noop)
			_, err := f.GetPublicKey(context.TODO(), []byte(test.key))

			if test.expErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
			}
		})
	}
}

func TestKeyFactoryPrivateKey(t *testing.T) {
	tests := map[string]struct {
		key    string
		expErr bool
	}{
		"Empty key should error.": {
			key:    "",
			expErr: true,
		},

		"Invalid key should error.": {
			key:    "---",
			expErr: true,
		},

		"RSA keys should be valid.": {
			key: `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAx1Ile9NsUrl6Wu6S8HsFFIG8YgXYKXsiwozeTJUNkVvCffUwCgIy
jlUzKBaAJnk6su4Skr5hzrDDEIKJYJvrO8zpcMrqbzGoWf6gil6MLY8JomejyxppA2jXX4
kzrxCSAq4d37/O1Ns6bngW9e07by3m3HIUJpTpa+IXMGQiKzkYlJUisXrOjqgtXLVZLAp9
WbaIASgl4ZNIkXnZtD79pjzOmuGTDRpAKLKEsaaYfs+i4dSgHpwO6UtkUJ73EMz38wkvI5
Xm+N2Z/RdgKhm75wSsS80XIqvEurAz6TcDstWaz9ZnlsWG0+s04yOgmzGZjcQA0Zqc/UsI
HL6kwE7X0mtBiYI6ywOMbO+Jp1zuU+SfCdgS/ijk1veD0OVBxko0JM7mZnKS1fNKuBkFEC
Wj1OcWzt/YYYmhfb3drEdAF5dqRKrttraxCl723LelWPSLnOdAxGzE3A8Fv7vC+h86XtN7
yHYY45NPxsO+/tiV3m5CCFc8JYnrIhJ2HlBQmVFRAAAFiDeeYrg3nmK4AAAAB3NzaC1yc2
EAAAGBAMdSJXvTbFK5elrukvB7BRSBvGIF2Cl7IsKM3kyVDZFbwn31MAoCMo5VMygWgCZ5
OrLuEpK+Yc6wwxCCiWCb6zvM6XDK6m8xqFn+oIpejC2PCaJno8saaQNo11+JM68QkgKuHd
+/ztTbOm54FvXtO28t5txyFCaU6WviFzBkIis5GJSVIrF6zo6oLVy1WSwKfVm2iAEoJeGT
SJF52bQ+/aY8zprhkw0aQCiyhLGmmH7PouHUoB6cDulLZFCe9xDM9/MJLyOV5vjdmf0XYC
oZu+cErEvNFyKrxLqwM+k3A7LVms/WZ5bFhtPrNOMjoJsxmY3EANGanP1LCBy+pMBO19Jr
QYmCOssDjGzviadc7lPknwnYEv4o5Nb3g9DlQcZKNCTO5mZyktXzSrgZBRAlo9TnFs7f2G
GJoX293axHQBeXakSq7ba2sQpe9ty3pVj0i5znQMRsxNwPBb+7wvofOl7Te8h2GOOTT8bD
vv7Yld5uQghXPCWJ6yISdh5QUJlRUQAAAAMBAAEAAAGAYBtL15jp8jlctduzHiEzIeAsZV
dMEzQ8XnJt/Z8hG6WS8gj3UNweZGLQd9Phlqt9kikY64jAwFiatas7ckm78umq5afxwgu/
kSUlY5KTJKSDkLtITvY9DFfRAU+2jAMBZClwXiKuKBRM6FcfOxVYQxNu7XxUGwZSRqKNa9
fcYdr17y65u7nrPv34YWtPw9yK9Gb+zQ/+s/XAV+TZBAAbbbyEIkoCDZ9KsFTjhoU9omeb
sihDzH6S8gpYJEeB+afaTI7jYQUZX4U4oa9XKGRWtXm3xeWiEJO75HmJfQ/xAHcxhad5Fb
SDuE/LTDYfZGtkGb+j/5ztr/pva4UkdfI15Nbwo0UBqDxmedDUIMD1yuYodmIGFr1TLhgD
9EG25AsRZ4OiIXOEtuRvsee8LUvRyf8iR/ce3Aawduad7Sh3nCIsjobg/T4f8hbZozJpBD
BSgpQRnKJEqw17l1Ertwt3G97g5WnVsGAbioTCRRLKd3DcQC9dSaY5Hn+yDYlgGHLBAAAA
wQDf/v4tYTCcZWM3xWKTxYP2My6z9cnh0FmsRNIAVY9BZkaUyytfDYr+TtbPPTfI1UO5du
trMVr1xSzTc7ASKXMo0hU4xL2bS5kOxAWFFnTY2U9cIczmg3Ayi3L4c3MAI9y2MnQhOqUd
nBvE3a8QlRao/vVRvXMS4fW5C/XhJ/wlii0gI/nvuOyTYjfHju2lVB5+hVU8S1xhIHhNih
o9gM2+vSgpIq+eLaYrcvdcrHNwl8W/MCWXm5I52yyCon+lWO8AAADBAOIonajE/BeOR6nM
AJ7gZLCn1uR1PJbOPte9aQunkUNidqcuRpOITDssrwBu6ulIrEjps37GFq3G4wYBTXQZPO
6g0NGtAesmCez5huPISlu/I0rmnn9JYFnyDIZA/B/eP75VtTkto7RWcUvCWuc3CI9oJBe9
tMk6HpjnERYKuACN4mTbbN2j5BIerCrlnDchDuEGrlohKaUvsjZzKl2Qfqvkf0y8cTZUx/
K5f8oQuJOixykBxUqVVPRgHhxg6GrGgwAAAMEA4Z77HvnsRL1uyS8silpmr/FmlNxkBeuu
IcUuv80IReenXCw44rlUKFXCtbdWd+HbuoSC/g0PmoAhq6LmDKQ0bsTzrnRbHdbo2Xgqi2
nxQayFPHXTb64NRlxLgpd6nj1ge4+Jy7/Dn8nnXu1tt1HnLouuWRUfKZHnwgsga6tRe4sU
otx4IUdzAvRecfMemHuM6bWiOSNIqv6j/daip8a+fb2gjDrL4z+68TPAW6A0UGgIBTfua/
jXeAb7OM001mCbAAAADXNsb2tAbmF1dGlsdXMBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----`,
			expErr: false,
		},

		"Ed25519 keys should be valid.": {
			key: `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD+eAqaC+s1fqgSqdpfw38dYl+19JKo3L+zqA+fI42bMgAAAJB553wJeed8
CQAAAAtzc2gtZWQyNTUxOQAAACD+eAqaC+s1fqgSqdpfw38dYl+19JKo3L+zqA+fI42bMg
AAAEAGCP9m77XsqyCKWeneoPvypurmMvo64UusJEA/K66FiP54CpoL6zV+qBKp2l/Dfx1i
X7X0kqjcv7OoD58jjZsyAAAADXNsb2tAbmF1dGlsdXM=
-----END OPENSSH PRIVATE KEY-----
			`,
			expErr: false,
		},

		"X25519 keys should be valid.": {
			key:    `AGE-SECRET-KEY-1J2DCTK0T408RJK2KX5QM3RLT4MFXEZYGP327CNP347PKTQ22UYUQXJ3N4X`,
			expErr: false,
		},

		"SSH key with passphrase.": {
			// `test` passphrase.
			key: `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAH2j4KRt
kXuaMFXvv+orO8AAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIHdAfN6rU4tOpjOU
dOxSJh0EJopkQYR6h5steO+6aigfAAAAkC6bk0RGsyZk5jv5gk2scZ7VlsT9FL1O3oS09J
yB25M0buFWbQmp/XsuuZgg2iKwyu9/5dhmRpj1PSLGYXRNbf4duWKbSH4oxSsFPs1dFpsq
ra3GQFKuCo5rQYJCQGbJ18YDUgNZXZqP9uz53AlXUaS+pH3YqHZhMTQ5uNsTKP0DfWTv3g
kBvzR+ftEy9KmPtg==
-----END OPENSSH PRIVATE KEY-----
`,
			expErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			f := age.NewFactory(nil, log.Noop)
			_, err := f.GetPrivateKey(context.TODO(), []byte(test.key))

			if test.expErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
			}
		})
	}
}
