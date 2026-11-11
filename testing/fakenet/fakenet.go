// Package fakenet is a fake NetworkConnector: it stands in for
// mautrix-meta's MetaConnector so the sink can be driven through every
// bridgev2 path (messages, edits, reactions, deletes, receipts, backfill)
// without a real account. Outbound sends are answered with a success, a
// certain failure or a timeout to exercise the accepted/rejected/unknown
// mapping.
package fakenet

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"

	"go.mau.fi/util/configupgrade"
)

// OwnerRemoteID is the fake network id of the logged-in owner.
const OwnerRemoteID = networkid.UserID("owner-remote")

// LoginID is the fake login's id.
const LoginID = networkid.UserLoginID("fake-login")

// SendMode controls how the fake answers outbound sends.
type SendMode int

const (
	ModeOK SendMode = iota
	ModeFailCertain
	ModeTimeout
)

// SentRecord is one outbound call the fake network received.
type SentRecord struct {
	Kind   string `json:"kind"`
	Portal string `json:"portal"`
	Text   string `json:"text,omitempty"`
	Emoji  string `json:"emoji,omitempty"`
	Target string `json:"target,omitempty"`
	TxnID  string `json:"txnId,omitempty"`
}

// Network is a fake bridgev2.NetworkConnector.
type Network struct {
	br     *bridgev2.Bridge
	Client *Client
}

func New() *Network {
	return &Network{Client: &Client{}}
}

func (n *Network) Init(br *bridgev2.Bridge) { n.br = br; n.Client.br = br }
func (n *Network) Start(ctx context.Context) error {
	return nil
}

func (n *Network) GetName() bridgev2.BridgeName {
	return bridgev2.BridgeName{
		DisplayName:      "FakeNet",
		NetworkURL:       "https://fakenet.invalid",
		NetworkID:        "fakenet",
		BeeperBridgeType: "bridge-lab/fakenet",
	}
}

func (n *Network) GetDBMetaTypes() database.MetaTypes { return database.MetaTypes{} }

func (n *Network) GetBridgeInfoVersion() (info, capabilities int) { return 1, 1 }

func (n *Network) GetCapabilities() *bridgev2.NetworkGeneralCapabilities {
	return &bridgev2.NetworkGeneralCapabilities{}
}

func (n *Network) GetConfig() (string, any, configupgrade.Upgrader) { return "", nil, nil }

func (n *Network) LoadUserLogin(ctx context.Context, login *bridgev2.UserLogin) error {
	login.Client = n.Client
	n.Client.logins = append(n.Client.logins, login)
	return nil
}

func (n *Network) GetLoginFlows() []bridgev2.LoginFlow { return nil }

func (n *Network) CreateLogin(ctx context.Context, user *bridgev2.User, flowID string) (bridgev2.LoginProcess, error) {
	return nil, fmt.Errorf("fakenet has no interactive login")
}

// Client is the fake NetworkAPI.
type Client struct {
	br     *bridgev2.Bridge
	logins []*bridgev2.UserLogin

	mu        sync.Mutex
	Mode      SendMode
	Sent      []SentRecord
	Connected bool
	LoggedOut bool
	history   map[networkid.PortalID][]*bridgev2.BackfillMessage
}

var _ bridgev2.BackfillingNetworkAPI = (*Client)(nil)

// SetHistory gives a chat older messages (oldest first): the chat becomes
// backfillable and FetchMessages pages backwards through them.
func (c *Client) SetHistory(portal networkid.PortalID, msgs []*bridgev2.BackfillMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.history == nil {
		c.history = map[networkid.PortalID][]*bridgev2.BackfillMessage{}
	}
	c.history[portal] = msgs
}

func (c *Client) FetchMessages(ctx context.Context, params bridgev2.FetchMessagesParams) (*bridgev2.FetchMessagesResponse, error) {
	c.mu.Lock()
	hist := c.history[params.Portal.ID]
	c.mu.Unlock()
	if params.Forward {
		return &bridgev2.FetchMessagesResponse{Forward: true}, nil
	}
	c.record(SentRecord{Kind: "fetch", Portal: string(params.Portal.ID)})
	end := len(hist)
	if params.AnchorMessage != nil {
		end = 0
		for i, m := range hist {
			if m.Timestamp.Before(params.AnchorMessage.Timestamp) {
				end = i + 1
			}
		}
	}
	start := max(0, end-params.Count)
	return &bridgev2.FetchMessagesResponse{Messages: hist[start:end], HasMore: start > 0}, nil
}

func (c *Client) record(r SentRecord) {
	c.mu.Lock()
	c.Sent = append(c.Sent, r)
	c.mu.Unlock()
}

// SentRecords returns a copy of the recorded outbound calls.
func (c *Client) SentRecords() []SentRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]SentRecord(nil), c.Sent...)
}

func (c *Client) Connect(ctx context.Context) {
	c.mu.Lock()
	c.Connected = true
	c.mu.Unlock()
}
func (c *Client) Disconnect() {
	c.mu.Lock()
	c.Connected = false
	c.mu.Unlock()
}
func (c *Client) IsLoggedIn() bool { return true }
func (c *Client) LogoutRemote(ctx context.Context) {
	c.mu.Lock()
	c.LoggedOut = true
	c.mu.Unlock()
}

// WasLoggedOut reports whether LogoutRemote ran.
func (c *Client) WasLoggedOut() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.LoggedOut
}
func (c *Client) IsThisUser(ctx context.Context, userID networkid.UserID) bool {
	return userID == OwnerRemoteID
}

func (c *Client) GetChatInfo(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.ChatInfo, error) {
	name := fmt.Sprintf("Fake chat %s", portal.ID)
	c.mu.Lock()
	_, canBackfill := c.history[portal.ID]
	c.mu.Unlock()
	return &bridgev2.ChatInfo{Name: &name, CanBackfill: canBackfill}, nil
}

func (c *Client) GetUserInfo(ctx context.Context, ghost *bridgev2.Ghost) (*bridgev2.UserInfo, error) {
	name := fmt.Sprintf("Ghost %s", ghost.ID)
	return &bridgev2.UserInfo{Name: &name}, nil
}

func (c *Client) GetCapabilities(ctx context.Context, portal *bridgev2.Portal) *event.RoomFeatures {
	return &event.RoomFeatures{}
}

var errCertainRefusal = bridgev2.WrapErrorInStatus(errors.New("simulated provider refusal")).WithIsCertain(true).WithStatus(event.MessageStatusFail)

func (c *Client) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) {
	txnID := string(msg.Event.Unsigned.TransactionID)
	c.record(SentRecord{Kind: "message", Portal: string(msg.Portal.ID), Text: msg.Content.Body, TxnID: txnID})
	switch c.Mode {
	case ModeFailCertain:
		return nil, errCertainRefusal
	case ModeTimeout:
		time.Sleep(600 * time.Millisecond)
		return nil, errors.New("simulated network timeout")
	}
	return &bridgev2.MatrixMessageResponse{
		DB: &database.Message{
			ID:        networkid.MessageID("remote-" + txnID),
			SenderID:  OwnerRemoteID,
			Timestamp: time.Now(),
		},
	}, nil
}

func (c *Client) PreHandleMatrixReaction(ctx context.Context, msg *bridgev2.MatrixReaction) (bridgev2.MatrixReactionPreResponse, error) {
	emoji := msg.Content.RelatesTo.Key
	return bridgev2.MatrixReactionPreResponse{
		SenderID: OwnerRemoteID,
		EmojiID:  networkid.EmojiID(emoji),
		Emoji:    emoji,
	}, nil
}

func (c *Client) HandleMatrixReaction(ctx context.Context, msg *bridgev2.MatrixReaction) (*database.Reaction, error) {
	emoji := msg.Content.RelatesTo.Key
	c.record(SentRecord{Kind: "reaction", Portal: string(msg.Portal.ID), Emoji: emoji, TxnID: string(msg.Event.Unsigned.TransactionID)})
	if c.Mode == ModeFailCertain {
		return nil, errCertainRefusal
	}
	return &database.Reaction{}, nil
}

func (c *Client) HandleMatrixReactionRemove(ctx context.Context, msg *bridgev2.MatrixReactionRemove) error {
	c.record(SentRecord{Kind: "reaction_remove", Portal: string(msg.Portal.ID), Emoji: string(msg.TargetReaction.EmojiID), TxnID: string(msg.Event.Unsigned.TransactionID)})
	return nil
}

func (c *Client) HandleMatrixEdit(ctx context.Context, msg *bridgev2.MatrixEdit) error {
	c.record(SentRecord{Kind: "edit", Portal: string(msg.Portal.ID), Text: msg.Content.Body, TxnID: string(msg.Event.Unsigned.TransactionID)})
	return nil
}

func (c *Client) HandleMatrixMessageRemove(ctx context.Context, msg *bridgev2.MatrixMessageRemove) error {
	c.record(SentRecord{Kind: "message_remove", Portal: string(msg.Portal.ID), Target: string(msg.TargetMessage.ID)})
	return nil
}

func (c *Client) HandleMatrixReadReceipt(ctx context.Context, msg *bridgev2.MatrixReadReceipt) error {
	c.record(SentRecord{Kind: "read_receipt", Portal: string(msg.Portal.ID), Target: string(msg.EventID)})
	return nil
}
