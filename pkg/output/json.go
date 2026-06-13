package output

import (
	"encoding/json"
	"os"

	"github.com/byjanke/driftnet2/pkg/protocol"
)

func WriteJSON(creds []protocol.Credential, filename string) error {
	output := struct {
		Credentials []protocol.Credential `json:"credentials"`
		Count       int                   `json:"count"`
	}{
		Credentials: creds,
		Count:       len(creds),
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}
