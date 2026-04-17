// Package strfry defines the JSON wire types exchanged with the strfry relay
// over stdin/stdout. See https://github.com/hoytech/strfry/blob/master/docs/plugins.md.
package strfry

type Event struct {
	ID        string     `json:"id"`
	Pubkey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

type SourceType string

const (
	SourceIP4    SourceType = "IP4"
	SourceIP6    SourceType = "IP6"
	SourceImport SourceType = "Import"
	SourceStream SourceType = "Stream"
	SourceSync   SourceType = "Sync"
	SourceStored SourceType = "Stored"
)

// IsLiveClient reports whether the event originates from a live client write
// (versus replication/backfill traffic that should bypass scoring).
func (s SourceType) IsLiveClient() bool {
	return s == SourceIP4 || s == SourceIP6
}

type Message struct {
	Type       string     `json:"type"`
	Event      *Event     `json:"event"`
	ReceivedAt int64      `json:"receivedAt"`
	SourceType SourceType `json:"sourceType"`
	SourceInfo string     `json:"sourceInfo"`
	Authed     string     `json:"authed,omitempty"`
}

type Action string

const (
	ActionAccept        Action = "accept"
	ActionReject        Action = "reject"
	ActionShadowReject  Action = "shadowReject"
)

type Response struct {
	ID     string `json:"id"`
	Action Action `json:"action"`
	Msg    string `json:"msg,omitempty"`
}
