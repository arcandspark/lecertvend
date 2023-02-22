package lecertvend

import (
	"context"
	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns"
)

func WriteTXT(token string, zone string, name string, content string) error {
	provider := cloudflare.Provider{APIToken: token}
	_, err := provider.SetRecords(context.Background(), zone, []libdns.Record{
		{
			Type:  "TXT",
			Name:  name,
			Value: content,
			TTL:   60,
		},
	})

	return err
}

func DeleteTXT(token string, zone string, name string) error {
	provider := cloudflare.Provider{APIToken: token}
	_, err := provider.DeleteRecords(context.Background(), zone, []libdns.Record{
		{
			Type: "TXT",
			Name: name,
		},
	})
	return err
}
