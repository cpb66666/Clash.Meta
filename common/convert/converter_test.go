package convert

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// https://v2.hysteria.network/zh/docs/developers/URI-Scheme/
func TestConvertsV2Ray_normal(t *testing.T) {
	hy2test := "hysteria2://letmein@example.com:8443/?insecure=1&obfs=salamander&obfs-password=gawrgura&pinSHA256=deadbeef&sni=real.example.com&up=114&down=514&alpn=h3,h4#hy2test"

	expected := []map[string]interface{}{
		{
			"name":             "hy2test",
			"type":             "hysteria2",
			"server":           "example.com",
			"port":             "8443",
			"sni":              "real.example.com",
			"obfs":             "salamander",
			"obfs-password":    "gawrgura",
			"alpn":             []string{"h3", "h4"},
			"password":         "letmein",
			"up":               "114",
			"down":             "514",
			"skip-cert-verify": true,
			"fingerprint":      "deadbeef",
		},
	}

	proxies, err := ConvertsV2Ray([]byte(hy2test))

	assert.Nil(t, err)
	assert.Equal(t, expected, proxies)
}

func TestConvertsV2Ray_Phantom(t *testing.T) {
	uri1 := "phantom://1001:secret-uuid-1@23.144.20.116:443?pub=pKtiTTTJwlT1zo4E3Tbphz10cQUX43Zu0UeWZvpt2SE&sni=www.microsoft.com,learn.microsoft.com&fp=chrome&min-idle=1&max-idle=6&udp=true#%E7%BE%8E%E5%9B%BD%E8%8A%82%E7%82%B9"
	uri2 := "phantom://1002:secret-uuid-2@example.com?pub=pKtiTTTJwlT1zo4E3Tbphz10cQUX43Zu0UeWZvpt2SE&udp=false#%E7%BE%8E%E5%9B%BD%E8%8A%82%E7%82%B9"
	badMissingPub := "phantom://1003:secret@1.2.3.4:443?sni=www.microsoft.com#bad1"
	badZeroUID := "phantom://0:secret@1.2.3.4:443?pub=abc#bad2"
	badPort := "phantom://1004:secret@1.2.3.4:99999?pub=abc#bad3"
	badNoSecret := "phantom://1005@1.2.3.4:443?pub=abc#bad4"

	subText := strings.Join([]string{
		uri1,
		badMissingPub,
		badZeroUID,
		badPort,
		badNoSecret,
		uri2,
	}, "\n")
	encodedSub := base64.StdEncoding.EncodeToString([]byte(subText))

	proxies, err := ConvertsV2Ray([]byte(encodedSub))
	assert.Nil(t, err)
	assert.Len(t, proxies, 2)

	assert.Equal(t, map[string]any{
		"name":       "美国节点",
		"type":       "phantom",
		"server":     "23.144.20.116",
		"port":       "443",
		"user-id":    uint32(1001),
		"secret":     "secret-uuid-1",
		"public-key": "pKtiTTTJwlT1zo4E3Tbphz10cQUX43Zu0UeWZvpt2SE",
		"sni":        []string{"www.microsoft.com", "learn.microsoft.com"},
		"min-idle":   1,
		"max-idle":   6,
		"udp":        true,
	}, proxies[0])

	assert.Equal(t, map[string]any{
		"name":       "美国节点-01",
		"type":       "phantom",
		"server":     "example.com",
		"port":       "443",
		"user-id":    uint32(1002),
		"secret":     "secret-uuid-2",
		"public-key": "pKtiTTTJwlT1zo4E3Tbphz10cQUX43Zu0UeWZvpt2SE",
		"udp":        false,
	}, proxies[1])

	// All malformed lines should fail gracefully with format invalid error and no panic
	_, err = ConvertsV2Ray([]byte(strings.Join([]string{badMissingPub, badZeroUID, badPort, badNoSecret}, "\n")))
	assert.Error(t, err)
}
