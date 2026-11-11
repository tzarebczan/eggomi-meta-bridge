// Package sink is the MatrixConnector that replaces the homeserver side of
// bridgev2. It fakes a single owner user, one bot and ghost
// users; converts every Matrix-side call into Eggomi domain events journaled
// in the outbox; and implements the outbound operation table's commit point
// (PROTOCOL.md section 5.1) through the ops package. There is no homeserver, no double
// puppeting, no typing or presence.
package sink

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/tzarebczan/eggomi-meta-bridge/media"
	"github.com/tzarebczan/eggomi-meta-bridge/ops"
	"github.com/tzarebczan/eggomi-meta-bridge/outbox"
)

// ServerName is the fake Matrix server name used in all ids.
const ServerName = "eggomi.local"

// OwnerMXID is the single Matrix-side user the sink fakes.
const OwnerMXID = id.UserID("@owner:eggomi.local")

// BotMXID is the bridge bot the sink fakes.
const BotMXID = id.UserID("@bridgebot:eggomi.local")

// Coded errors the link layer maps to protocol codes.
var (
	// ErrDuplicateOp: the op id was already committed; nothing is re-sent.
	ErrDuplicateOp = ops.ErrDuplicate
	// ErrOpMismatch: the op id was committed with another payload.
	ErrOpMismatch = ops.ErrMismatch
	// ErrUnknownConversation: no portal for the given remote conversation id.
	ErrUnknownConversation = errors.New("unknown_conversation")
	// ErrTargetGone: the reply/react/markRead target is unknown to the bridge.
	ErrTargetGone = errors.New("target_gone")
	// ErrNotLoggedIn: no user login exists.
	ErrNotLoggedIn = errors.New("not_logged_in")
)

// reactionEventPrefix marks every event id the sink assigns to a reaction, so
// a redaction of one is classified as reaction_remove without any state
// (restart-safe). bridgev2 only ever redacts reactions and messages.
const reactionEventPrefix = "$mbr-"

// Sink implements bridgev2.MatrixConnector with no homeserver.
type Sink struct {
	Out   *outbox.Outbox
	Ops   *ops.Table
	Media *media.Cache

	br      *bridgev2.Bridge
	bot     *Intent
	portals sync.Map // room id -> remote portal id (stable, never invalidated)

	stateMu   sync.Mutex
	lastState status.BridgeState
}

// New builds the sink on the shared journal, op table and media cache.
func New(out *outbox.Outbox, opTable *ops.Table, cache *media.Cache) *Sink {
	s := &Sink{Out: out, Ops: opTable, Media: cache}
	s.bot = &Intent{sink: s, mxid: BotMXID}
	return s
}

func (s *Sink) emit(kind, portal string, data map[string]any) {
	if _, err := s.Out.Append(kind, portal, data); err != nil {
		// The journal is the delivery path; a failed append must be loud.
		// bridgev2 logs the returned error of the calling MatrixAPI method.
		panic(fmt.Sprintf("outbox append failed: %v", err))
	}
}

// remotePortal maps a Matrix room id to the portal's remote id, cached.
func (s *Sink) remotePortal(ctx context.Context, roomID id.RoomID) string {
	if v, ok := s.portals.Load(roomID); ok {
		return v.(string)
	}
	remote := string(roomID) // pre-portal-creation fallback (CreateRoom event)
	portal, err := s.br.DB.Portal.GetByMXID(ctx, roomID)
	if err == nil && portal != nil {
		remote = string(portal.PortalKey.ID)
		s.portals.Store(roomID, remote)
	}
	return remote
}

// remoteMessage resolves a Matrix event id to the remote message id.
func (s *Sink) remoteMessage(ctx context.Context, eventID id.EventID) string {
	msg, err := s.br.DB.Message.GetPartByMXID(ctx, eventID)
	if err == nil && msg != nil {
		return string(msg.ID)
	}
	return ""
}

func deterministic(prefix string, parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return prefix + hex.EncodeToString(h.Sum(nil))[:40]
}

// --- bridgev2.MatrixConnector ---

func (s *Sink) Init(br *bridgev2.Bridge)        { s.br = br }
func (s *Sink) Start(ctx context.Context) error { return nil }
func (s *Sink) PreStop()                        {}
func (s *Sink) Stop()                           {}

func (s *Sink) GetCapabilities() *bridgev2.MatrixCapabilities {
	return &bridgev2.MatrixCapabilities{BatchSending: true, ArbitraryMemberChange: true}
}

func (s *Sink) ParseGhostMXID(userID id.UserID) (networkid.UserID, bool) {
	str := string(userID)
	suffix := ":" + ServerName
	if len(str) > 5+len(suffix) && str[:5] == "@fbm_" && str[len(str)-len(suffix):] == suffix {
		return networkid.UserID(str[5 : len(str)-len(suffix)]), true
	}
	return "", false
}

func (s *Sink) FormatGhostMXID(userID networkid.UserID) id.UserID {
	return id.UserID(fmt.Sprintf("@fbm_%s:%s", userID, ServerName))
}

func (s *Sink) GhostIntent(userID networkid.UserID) bridgev2.MatrixAPI {
	return &Intent{sink: s, mxid: s.FormatGhostMXID(userID)}
}

// NewUserIntent refuses double puppeting (one faked owner). The
// bridge falls back to the bot intent for own-user actions; bot-intent
// MarkRead is therefore the owner's read.
func (s *Sink) NewUserIntent(ctx context.Context, userID id.UserID, accessToken string) (bridgev2.MatrixAPI, string, error) {
	return nil, "", fmt.Errorf("no double puppeting in the sink")
}

func (s *Sink) BotIntent() bridgev2.MatrixAPI { return s.bot }

// State is the newest bridge state the bridge reported.
func (s *Sink) State() status.BridgeState {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.lastState
}

func (s *Sink) SendBridgeStatus(ctx context.Context, state *status.BridgeState) error {
	s.stateMu.Lock()
	s.lastState = *state
	s.stateMu.Unlock()
	data := map[string]any{"state": string(state.StateEvent)}
	if state.Error != "" {
		data["error"] = string(state.Error)
	}
	if state.UserID != "" {
		data["user"] = string(state.UserID)
	}
	if state.RemoteID != "" {
		data["login"] = string(state.RemoteID)
	}
	s.emit("state", "", data)
	return nil
}

// SendMessageStatus settles an outbound operation (PROTOCOL.md section 5.1): success with
// the remote id is accepted, a certain failure is rejected, everything else
// is unknown and never retried.
func (s *Sink) SendMessageStatus(ctx context.Context, st *bridgev2.MessageStatus, evt *bridgev2.MessageStatusEventInfo) {
	opID := evt.TransactionID
	if opID == "" {
		return
	}
	state, remoteID, code := "", "", ""
	switch {
	case st.Status == event.MessageStatusSuccess:
		state = ops.StateAccepted
		if evt.SourceEventID != "" {
			remoteID = s.remoteMessage(ctx, evt.SourceEventID)
		}
	case st.Status == event.MessageStatusFail && st.IsCertain:
		state = ops.StateRejected
		code = string(st.ErrorReason)
		if code == "" {
			code = "provider_refused"
		}
	default:
		state = ops.StateUnknown
		code = string(st.ErrorReason)
		if code == "" {
			code = "provider_uncertain"
		}
	}
	transitioned, err := s.Ops.Settle(ctx, opID, state, remoteID, code)
	if err != nil || !transitioned {
		return
	}
	s.emit("op", "", map[string]any{"opId": opID, "state": state, "remoteId": remoteID, "code": code})
}

// RecoverOps settles every operation left at the commit point by a crash or
// stop as unknown: after the commit point, a crash is unknown.
func (s *Sink) RecoverOps(ctx context.Context) error {
	pending, err := s.Ops.Committed(ctx)
	if err != nil {
		return err
	}
	for _, op := range pending {
		ok, err := s.Ops.Settle(ctx, op.ID, ops.StateUnknown, "", "bridge_restarted")
		if err == nil && ok {
			s.emit("op", "", map[string]any{"opId": op.ID, "state": ops.StateUnknown, "code": "bridge_restarted"})
		}
	}
	return nil
}

// Reconcile implements the read-only check behind messenger.reconcile
// (PROTOCOL.md section 5.2): does a message row exist for the send's deterministic event
// id? If so the op settles accepted with its remote id.
func (s *Sink) Reconcile(ctx context.Context, opID string) (*ops.Op, error) {
	op, err := s.Ops.Get(ctx, opID)
	if err != nil || op == nil {
		return op, err
	}
	if op.State != ops.StateUnknown {
		return op, nil
	}
	msg, err := s.br.DB.Message.GetPartByMXID(ctx, id.EventID(deterministic("$op-", opID)))
	if err != nil || msg == nil {
		return op, err
	}
	if ok, err := s.Ops.Settle(ctx, opID, ops.StateAccepted, string(msg.ID), ""); err == nil && ok {
		op.State = ops.StateAccepted
		op.RemoteID = string(msg.ID)
		s.emit("op", "", map[string]any{"opId": opID, "state": ops.StateAccepted, "remoteId": op.RemoteID})
	}
	return op, nil
}

// Media refs, the file part of the sink's content URIs and what the keeper
// passes to media.get: "c" + a cache id for bytes the bridge already holds,
// "d" + base64url(network media id) for direct media fetched on demand.
const (
	RefCached = 'c'
	RefDirect = 'd'
)

const mxcPrefix = "mxc://" + ServerName + "/"

// MediaRef extracts the media ref from one of the sink's content URIs.
func MediaRef(uri id.ContentURIString) (string, bool) {
	ref, ok := strings.CutPrefix(string(uri), mxcPrefix)
	return ref, ok && len(ref) > 1 && (ref[0] == RefCached || ref[0] == RefDirect)
}

// DirectMediaID decodes a direct media ref.
func DirectMediaID(ref string) (networkid.MediaID, bool) {
	if len(ref) < 2 || ref[0] != RefDirect {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(ref[1:])
	return networkid.MediaID(raw), err == nil && len(raw) > 0
}

// GenerateContentURI names direct media (connector SetUseDirectMedia): the
// bytes stay at the network until media.get asks for them.
func (s *Sink) GenerateContentURI(ctx context.Context, mediaID networkid.MediaID) (id.ContentURIString, error) {
	return id.ContentURIString(mxcPrefix + string(RefDirect) + base64.RawURLEncoding.EncodeToString(mediaID)), nil
}

func (s *Sink) ParseContentURI(ctx context.Context, contentURI id.ContentURIString) (networkid.MediaID, error) {
	ref, ok := MediaRef(contentURI)
	if !ok {
		return nil, fmt.Errorf("not a sink content URI")
	}
	if mediaID, ok := DirectMediaID(ref); ok {
		return mediaID, nil
	}
	return networkid.MediaID(ref), nil
}

func (s *Sink) GetPowerLevels(ctx context.Context, roomID id.RoomID) (*event.PowerLevelsEventContent, error) {
	return &event.PowerLevelsEventContent{}, nil
}

func (s *Sink) GetMembers(ctx context.Context, roomID id.RoomID) (map[id.UserID]*event.MemberEventContent, error) {
	return map[id.UserID]*event.MemberEventContent{}, nil
}

func (s *Sink) GetMemberInfo(ctx context.Context, roomID id.RoomID, userID id.UserID) (*event.MemberEventContent, error) {
	return &event.MemberEventContent{Membership: event.MembershipJoin}, nil
}

func (s *Sink) BatchSend(ctx context.Context, roomID id.RoomID, req *mautrix.ReqBeeperBatchSend, extras []*bridgev2.MatrixSendExtra) (*mautrix.RespBeeperBatchSend, error) {
	resp := &mautrix.RespBeeperBatchSend{}
	for i, evt := range req.Events {
		extra := &bridgev2.MatrixSendExtra{}
		if i < len(extras) && extras[i] != nil {
			extra = extras[i]
		}
		evtID := id.EventID(deterministic("$mbb-", string(roomID), fmt.Sprint(i)))
		s.convertMessage(ctx, roomID, evtID, evt.Type, &event.Content{Parsed: evt.Content.Parsed, Raw: evt.Content.Raw}, extra, "history")
		resp.EventIDs = append(resp.EventIDs, evtID)
	}
	return resp, nil
}

func (s *Sink) GenerateDeterministicRoomID(portalKey networkid.PortalKey) id.RoomID {
	roomID := id.RoomID(deterministic("!mb-", string(portalKey.ID), string(portalKey.Receiver)) + ":" + ServerName)
	// bridgev2 asks for the id just before CreateRoom, when the portal row
	// has no room yet: remember the mapping so the conversation event names
	// the remote conversation.
	s.portals.Store(roomID, string(portalKey.ID))
	return roomID
}

func (s *Sink) GenerateDeterministicEventID(roomID id.RoomID, portalKey networkid.PortalKey, messageID networkid.MessageID, partID networkid.PartID) id.EventID {
	return id.EventID(deterministic("$mb-", string(messageID), string(partID), string(portalKey.Receiver)))
}

func (s *Sink) GenerateReactionEventID(roomID id.RoomID, targetMessage *database.Message, sender networkid.UserID, emojiID networkid.EmojiID) id.EventID {
	return id.EventID(deterministic(reactionEventPrefix, string(targetMessage.ID), string(sender), string(emojiID)))
}

func (s *Sink) ServerName() string { return ServerName }

// convertMessage turns one Matrix-side message call into a domain event.
// evtID is the id the sink assigned (or will return) for the event.
func (s *Sink) convertMessage(ctx context.Context, roomID id.RoomID, evtID id.EventID, eventType event.Type, content *event.Content, extra *bridgev2.MatrixSendExtra, source string) {
	if source == "" {
		source = "live"
	}
	portal := s.remotePortal(ctx, roomID)
	data := map[string]any{"source": source, "eventId": string(evtID)}
	if extra != nil {
		if extra.TransactionID != "" {
			data["writeKey"] = string(extra.TransactionID)
		}
		if extra.MessageMeta != nil {
			data["remoteId"] = string(extra.MessageMeta.ID)
			data["sender"] = string(extra.MessageMeta.SenderID)
			data["timestamp"] = extra.MessageMeta.Timestamp.UnixMilli()
		}
	}
	switch eventType {
	case event.EventMessage, event.EventSticker:
		msg := content.AsMessage()
		if rel := msg.RelatesTo; rel != nil && rel.Type == event.RelReplace {
			newBody := ""
			if msg.NewContent != nil {
				newBody = msg.NewContent.Body
			}
			s.emit("edit", portal, map[string]any{
				"target":   string(rel.EventID),
				"targetId": s.remoteMessage(ctx, rel.EventID),
				"text":     newBody,
				"source":   source,
			})
			return
		}
		data["text"] = msg.Body
		data["msgtype"] = string(msg.MsgType)
		if msg.FileName != "" {
			data["fileName"] = msg.FileName
		}
		if ref, ok := MediaRef(msg.URL); ok {
			data["mediaRef"] = ref
			if msg.Info != nil {
				if msg.Info.MimeType != "" {
					data["mimeType"] = msg.Info.MimeType
				}
				if msg.Info.Size > 0 {
					data["size"] = msg.Info.Size
				}
			}
		}
		if rel := msg.RelatesTo; rel != nil && rel.InReplyTo != nil {
			data["replyTo"] = string(rel.InReplyTo.EventID)
			data["replyToId"] = s.remoteMessage(ctx, rel.InReplyTo.EventID)
		}
		s.emit("item", portal, data)
	case event.EventReaction:
		rc := content.AsReaction()
		s.emit("reaction", portal, map[string]any{
			"target":   string(rc.RelatesTo.EventID),
			"targetId": s.remoteMessage(ctx, rc.RelatesTo.EventID),
			"emoji":    rc.RelatesTo.Key,
			"eventId":  string(evtID),
			"source":   source,
		})
	case event.EventRedaction:
		// The target rides in Parsed; Raw may be empty.
		var redacts id.EventID
		if rc, ok := content.Parsed.(*event.RedactionEventContent); ok && rc.Redacts != "" {
			redacts = rc.Redacts
		} else if raw, _ := content.Raw["redacts"].(string); raw != "" {
			redacts = id.EventID(raw)
		}
		if strings.HasPrefix(string(redacts), reactionEventPrefix) {
			s.emit("reaction_remove", portal, map[string]any{"eventId": string(redacts)})
		} else {
			s.emit("delete", portal, map[string]any{
				"target":   string(redacts),
				"targetId": s.remoteMessage(ctx, redacts),
			})
		}
	default:
		// polls, payments, calls and everything else land as system items
		// keeper-side; the raw type is all they need.
		s.emit("item", portal, map[string]any{
			"source": source, "eventId": string(evtID), "msgtype": "m.notice",
			"system": eventType.Type,
		})
	}
}

// --- outbound commands (called by the core from link requests) ---

// resolvePortal maps a remote conversation id to its portal and room.
func (s *Sink) resolvePortal(ctx context.Context, login *bridgev2.UserLogin, conversation networkid.PortalID) (*database.Portal, error) {
	portal, err := s.br.DB.Portal.GetByKey(ctx, networkid.PortalKey{ID: conversation, Receiver: login.ID})
	if err != nil {
		return nil, err
	}
	if portal == nil || portal.MXID == "" {
		return nil, ErrUnknownConversation
	}
	return portal, nil
}

// beginOp is the commit point for one outbound operation; the digest binds
// the op id to everything that would be sent.
func (s *Sink) beginOp(ctx context.Context, opID, kind, conversation string, payload ...string) error {
	return s.Ops.Begin(ctx, opID, kind, conversation, deterministic("", append([]string{kind, conversation}, payload...)...))
}

func (s *Sink) queueRejected(opID string) {
	ctx := context.Background()
	if ok, _ := s.Ops.Settle(ctx, opID, ops.StateRejected, "", "queue_failed"); ok {
		s.emit("op", "", map[string]any{"opId": opID, "state": ops.StateRejected, "code": "queue_failed"})
	}
}

// SendText commits an outbound text operation and hands it to the bridge.
// replyTo, when non-empty, must resolve to a known message.
func (s *Sink) SendText(ctx context.Context, login *bridgev2.UserLogin, opID string, conversation networkid.PortalID, text string, replyTo networkid.MessageID) error {
	portal, err := s.resolvePortal(ctx, login, conversation)
	if err != nil {
		return err
	}
	var replyToEvent id.EventID
	if replyTo != "" {
		msg, err := s.br.DB.Message.GetFirstPartByID(ctx, login.ID, replyTo)
		if err != nil {
			return err
		}
		if msg == nil {
			return ErrTargetGone
		}
		replyToEvent = msg.MXID
	}
	if err := s.beginOp(ctx, opID, "send", string(conversation), text, string(replyTo)); err != nil {
		return err
	}
	content := &event.MessageEventContent{MsgType: event.MsgText, Body: text}
	if replyToEvent != "" {
		content.RelatesTo = (&event.RelatesTo{}).SetReplyTo(replyToEvent)
	}
	s.queueMatrixEvent(ctx, opID, portal.MXID, event.EventMessage, event.Content{Parsed: content})
	return nil
}

// SendReaction commits an outbound reaction and hands it to the bridge.
func (s *Sink) SendReaction(ctx context.Context, login *bridgev2.UserLogin, opID string, conversation networkid.PortalID, target networkid.MessageID, emoji string) error {
	portal, err := s.resolvePortal(ctx, login, conversation)
	if err != nil {
		return err
	}
	msg, err := s.br.DB.Message.GetFirstPartByID(ctx, login.ID, target)
	if err != nil {
		return err
	}
	if msg == nil {
		return ErrTargetGone
	}
	if err := s.beginOp(ctx, opID, "react", string(conversation), string(target), emoji); err != nil {
		return err
	}
	s.queueMatrixEvent(ctx, opID, portal.MXID, event.EventReaction, event.Content{Parsed: &event.ReactionEventContent{
		RelatesTo: event.RelatesTo{Type: event.RelAnnotation, EventID: msg.MXID, Key: emoji},
	}})
	return nil
}

// RemoveReaction redacts the owner's newest reaction to a message. It is the
// react command with emoji null.
func (s *Sink) RemoveReaction(ctx context.Context, login *bridgev2.UserLogin, opID string, conversation networkid.PortalID, target networkid.MessageID) error {
	portal, err := s.resolvePortal(ctx, login, conversation)
	if err != nil {
		return err
	}
	reactions, err := s.br.DB.Reaction.GetAllToMessage(ctx, login.ID, target)
	if err != nil {
		return err
	}
	own := reactions[:0]
	for _, r := range reactions {
		if login.Client != nil && login.Client.IsThisUser(ctx, r.SenderID) {
			own = append(own, r)
		}
	}
	if len(own) == 0 {
		return ErrTargetGone
	}
	if err := s.beginOp(ctx, opID, "unreact", string(conversation), string(target)); err != nil {
		return err
	}
	s.queueMatrixEvent(ctx, opID, portal.MXID, event.EventRedaction, event.Content{Parsed: &event.RedactionEventContent{
		Redacts: own[len(own)-1].MXID,
	}})
	return nil
}

// MarkRead queues the owner's read receipt (the markRead command).
// It carries no op: nothing is committed, nothing can be retried.
func (s *Sink) MarkRead(ctx context.Context, login *bridgev2.UserLogin, conversation networkid.PortalID, upTo networkid.MessageID) error {
	portal, err := s.resolvePortal(ctx, login, conversation)
	if err != nil {
		return err
	}
	msg, err := s.br.DB.Message.GetFirstPartByID(ctx, login.ID, upTo)
	if err != nil {
		return err
	}
	if msg == nil {
		return ErrTargetGone
	}
	receipts := event.ReceiptEventContent{}
	receipts.Set(msg.MXID, event.ReceiptTypeRead, OwnerMXID, event.ReadReceipt{Timestamp: time.Now()})
	evt := &event.Event{
		Sender:  OwnerMXID,
		Type:    event.EphemeralEventReceipt,
		RoomID:  portal.MXID,
		ID:      id.EventID(deterministic("$rcpt-", string(portal.MXID), fmt.Sprint(time.Now().UnixNano()))),
		Content: event.Content{Parsed: &receipts},
	}
	// bridgev2 ignores receipts unless marked ephemeral, and the
	// content must be a pointer.
	evt.Mautrix.EventSource = event.SourceEphemeral
	s.br.QueueMatrixEvent(ctx, evt)
	return nil
}

// queueMatrixEvent hands one committed operation to the bridge. A queue
// failure is a certain rejection (nothing reached the network).
func (s *Sink) queueMatrixEvent(ctx context.Context, opID string, roomID id.RoomID, eventType event.Type, content event.Content) {
	evt := &event.Event{
		Sender:   OwnerMXID,
		Type:     eventType,
		RoomID:   roomID,
		ID:       id.EventID(deterministic("$op-", opID)),
		Content:  content,
		Unsigned: event.Unsigned{TransactionID: opID},
	}
	if res := s.br.QueueMatrixEvent(ctx, evt); res.Error != nil {
		s.queueRejected(opID)
	}
}

// --- bridgev2.MatrixAPI ---

// Intent is the sink's MatrixAPI for one faked Matrix user.
type Intent struct {
	sink *Sink
	mxid id.UserID
}

func (i *Intent) GetMXID() id.UserID   { return i.mxid }
func (i *Intent) IsDoublePuppet() bool { return false }

func (i *Intent) SendMessage(ctx context.Context, roomID id.RoomID, eventType event.Type, content *event.Content, extra *bridgev2.MatrixSendExtra) (*mautrix.RespSendEvent, error) {
	// The event id comes first: every reaction id carries the reaction
	// prefix so later redactions classify state-free.
	var evtID id.EventID
	switch {
	case extra != nil && extra.MessageMeta != nil && extra.MessageMeta.MXID != "":
		evtID = extra.MessageMeta.MXID
	case extra != nil && extra.ReactionMeta != nil && extra.ReactionMeta.MXID != "":
		evtID = extra.ReactionMeta.MXID
	case eventType == event.EventReaction:
		rc := content.AsReaction()
		evtID = id.EventID(deterministic(reactionEventPrefix, string(roomID), string(rc.RelatesTo.EventID), rc.RelatesTo.Key, string(i.mxid)))
	default:
		evtID = id.EventID(deterministic("$mbx-", string(roomID), eventType.Type, fmt.Sprint(time.Now().UnixNano())))
	}
	i.sink.convertMessage(ctx, roomID, evtID, eventType, content, extra, "")
	return &mautrix.RespSendEvent{EventID: evtID}, nil
}

func (i *Intent) SendState(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, content *event.Content, ts time.Time) (*mautrix.RespSendEvent, error) {
	portal := i.sink.remotePortal(ctx, roomID)
	switch eventType {
	case event.StateRoomName:
		i.sink.emit("conversation", portal, map[string]any{"name": content.AsRoomName().Name})
	case event.StateTopic:
		i.sink.emit("conversation", portal, map[string]any{"topic": content.AsTopic().Topic})
	case event.StateRoomAvatar:
		i.sink.emit("conversation", portal, map[string]any{"avatar": string(content.AsRoomAvatar().URL)})
	case event.StateMember:
		data := map[string]any{"member": stateKey, "membership": string(content.AsMember().Membership)}
		if name := content.AsMember().Displayname; name != "" {
			data["displayname"] = name
		}
		i.sink.emit("member", portal, data)
	default:
		// m.bridge, power levels, encryption: not forwarded.
	}
	return &mautrix.RespSendEvent{EventID: id.EventID(deterministic("$mbs-", string(roomID), eventType.Type, stateKey))}, nil
}

func (i *Intent) MarkRead(ctx context.Context, roomID id.RoomID, eventID id.EventID, ts time.Time) error {
	// Ghost receipts are dropped. Own-user actions arrive on the
	// bot intent without double puppeting.
	if i.mxid == OwnerMXID || i.mxid == BotMXID {
		i.sink.emit("read", i.sink.remotePortal(ctx, roomID), map[string]any{
			"upTo":   string(eventID),
			"upToId": i.sink.remoteMessage(ctx, eventID),
			"at":     ts.UnixMilli(),
		})
	}
	return nil
}

func (i *Intent) MarkUnread(ctx context.Context, roomID id.RoomID, unread bool) error {
	return nil
}

func (i *Intent) MarkTyping(ctx context.Context, roomID id.RoomID, typingType bridgev2.TypingType, timeout time.Duration) error {
	return nil // typing is never forwarded
}

// DownloadMedia serves bytes the sink already holds (outbound media is not in
// v1; this only reads back cached uploads).
func (i *Intent) DownloadMedia(ctx context.Context, uri id.ContentURIString, file *event.EncryptedFileInfo) ([]byte, error) {
	ref, ok := MediaRef(uri)
	if !ok || ref[0] != RefCached {
		return nil, fmt.Errorf("not a cached media ref")
	}
	return i.sink.Media.Get(ref[1:])
}

func (i *Intent) DownloadMediaToFile(ctx context.Context, uri id.ContentURIString, file *event.EncryptedFileInfo, writable bool, callback func(*os.File) error) error {
	data, err := i.DownloadMedia(ctx, uri, file)
	if err != nil {
		return err
	}
	// The compartment's root is read-only; scratch files live in the cache dir.
	tmp, err := i.sink.Media.CreatePart()
	if err != nil {
		return err
	}
	defer i.sink.Media.Abort(tmp)
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if _, err = tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return callback(tmp)
}

func cachedURI(mediaID string) id.ContentURIString {
	return id.ContentURIString(mxcPrefix + string(RefCached) + mediaID)
}

func (i *Intent) UploadMedia(ctx context.Context, roomID id.RoomID, data []byte, fileName, mimeType string) (id.ContentURIString, *event.EncryptedFileInfo, error) {
	mediaID, err := i.sink.Media.Put(data)
	if err != nil {
		return "", nil, err
	}
	return cachedURI(mediaID), nil, nil
}

func (i *Intent) UploadMediaStream(ctx context.Context, roomID id.RoomID, size int64, requireFile bool, cb bridgev2.FileStreamCallback) (id.ContentURIString, *event.EncryptedFileInfo, error) {
	tmp, err := i.sink.Media.CreatePart()
	if err != nil {
		return "", nil, err
	}
	defer i.sink.Media.Abort(tmp)
	res, err := cb(tmp)
	if err != nil {
		return "", nil, err
	}
	var src io.Reader = tmp
	if res != nil && res.ReplacementFile != "" {
		repl, err := os.Open(res.ReplacementFile)
		if err != nil {
			return "", nil, err
		}
		defer os.Remove(res.ReplacementFile)
		defer repl.Close()
		src = repl
	} else if _, err = tmp.Seek(0, io.SeekStart); err != nil {
		return "", nil, err
	}
	mediaID, _, err := i.sink.Media.PutReader(src, -1)
	if err != nil {
		return "", nil, err
	}
	return cachedURI(mediaID), nil, nil
}

func (i *Intent) SetDisplayName(ctx context.Context, name string) error                 { return nil }
func (i *Intent) SetAvatarURL(ctx context.Context, avatarURL id.ContentURIString) error { return nil }
func (i *Intent) SetExtraProfileMeta(ctx context.Context, data any) error               { return nil }
func (i *Intent) SetProfile(ctx context.Context, data any) error                        { return nil }

func (i *Intent) CreateRoom(ctx context.Context, req *mautrix.ReqCreateRoom) (id.RoomID, error) {
	roomID := req.BeeperLocalRoomID
	if roomID == "" {
		roomID = id.RoomID(deterministic("!mbx-", fmt.Sprint(time.Now().UnixNano())) + ":" + ServerName)
	}
	i.sink.emit("conversation", i.sink.remotePortal(ctx, roomID), map[string]any{
		"room": string(roomID), "name": req.Name, "topic": req.Topic,
	})
	return roomID, nil
}

func (i *Intent) DeleteRoom(ctx context.Context, roomID id.RoomID, puppetsOnly bool) error {
	i.sink.emit("conversation_deleted", i.sink.remotePortal(ctx, roomID), nil)
	return nil
}

func (i *Intent) EnsureJoined(ctx context.Context, roomID id.RoomID, params ...bridgev2.EnsureJoinedParams) error {
	return nil
}

func (i *Intent) EnsureInvited(ctx context.Context, roomID id.RoomID, userID id.UserID) error {
	return nil
}

func (i *Intent) TagRoom(ctx context.Context, roomID id.RoomID, tag event.RoomTag, isTagged bool) error {
	return nil
}

func (i *Intent) MuteRoom(ctx context.Context, roomID id.RoomID, until time.Time) error {
	return nil
}

func (i *Intent) GetEvent(ctx context.Context, roomID id.RoomID, eventID id.EventID) (*event.Event, error) {
	return nil, fmt.Errorf("GetEvent not supported by the sink")
}
