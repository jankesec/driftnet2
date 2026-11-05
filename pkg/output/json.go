package output

import (
	"encoding/json"
	"time"

	"github.com/jankesec/driftnet2/internal/buildinfo"
	"github.com/jankesec/driftnet2/pkg/protocol"
)

type jsonOutput struct {
	Metadata    jsonMeta              `json:"metadata"`
	Credentials []protocol.Credential `json:"credentials"`
}

type jsonMeta struct {
	Tool       string    `json:"tool"`
	Version    string    `json:"version"`
	ExportedAt time.Time `json:"exported_at"`
	Count      int       `json:"count"`
}

func WriteJSON(creds []protocol.Credential, filename string) error {
	out := jsonOutput{
		Metadata: jsonMeta{
			Tool:       "driftnet2",
			Version:    buildinfo.Version,
			ExportedAt: time.Now(),
			Count:      len(creds),
		},
		Credentials: creds,
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}

	return WritePrivateFile(filename, data)
}
