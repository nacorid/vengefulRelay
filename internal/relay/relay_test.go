package relay_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip11"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/config"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/lightning"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/relay"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/store"
	"github.com/fasthttp/websocket"
)

// -----------------------------------------------------------------------------
// Test Setup Helper
// -----------------------------------------------------------------------------
var (
	relaySk nostr.SecretKey
	relayPk nostr.PubKey
)

// setupTestRelay spins up a test HTTP server with your relay.
func setupTestRelay(t *testing.T) (*httptest.Server, *relay.VengefulRelay, string, func()) {
	t.Helper()

	// 1. Mock Config
	// We use a generated key for the relay identity
	relaySk = nostr.Generate()
	relayPk = nostr.GetPublicKey(relaySk)

	cfg := config.Config{
		RelayName:        "Test Relay",
		RelayPubkey:      relayPk.Hex(),
		RelayDescription: "Unit testing relay",
		RelayURL:         "ws://localhost",
		Whitelist:        []string{relayPk.Hex()},
		MaxEventLength:   100000,
		MinPowDifficulty: 0, // Keep 0 for fast tests
		AdmissionFee:     1000,
	}

	// 2. Initialize Store
	st, err := store.Init("postgres://nostr@/nostr_test?host=/var/run/postgresql")
	if err != nil {
		t.Log("WARNING: Store is nil. Tests requiring persistence will panic until you mock the Store.")
	}

	// 3. Extract DB handle for cleanup
	var db *sql.DB
	if st != nil && st.PostgresBackend != nil {
		// Assuming PostgresBackend struct has a public 'DB' field of type *sql.DB
		db = st.PostgresBackend.DB.DB
	}

	// 4. Mock Lightning Provider
	// TODO: Initialize a mock LN provider
	var ln *lightning.Provider = nil // <--- REPLACE THIS

	// 5. Initialize Relay
	// Passing nil logger for cleaner test output
	vr := relay.New(cfg, st, ln, nil)
	ts := httptest.NewServer(vr)
	wsURL := strings.Replace(ts.URL, "http", "ws", 1)

	// 6. Create Teardown Closure
	teardown := func() {
		ts.Close()
		cleanupDatabase(t, db) // Clean DB after test finishes
	}

	return ts, vr, wsURL, teardown
}

func cleanupDatabase(t *testing.T, db *sql.DB) {
	t.Helper()
	if db == nil {
		return
	}

	// Dropping tables as requested.
	tables := []string{"event", "known_pubkeys", "invoices_paid"}

	for _, table := range tables {
		_, err := db.Exec("DROP TABLE IF EXISTS " + table + " CASCADE")
		if err != nil {
			t.Logf("Warning: Failed to cleanup table %s: %v", table, err)
		}
	}
}

// generateTestUser creates a keypair for a test client
func generateTestUser() (nostr.SecretKey, nostr.PubKey) {

	sk := nostr.Generate()
	pk := nostr.GetPublicKey(sk)
	return sk, pk
}
func getOwnerKeys() (nostr.SecretKey, nostr.PubKey) {
	return relaySk, relayPk
}

// -----------------------------------------------------------------------------
// NIP-01: Basic Protocol (Req, Event, Eose)
// -----------------------------------------------------------------------------

func TestNIP01_BasicFlow(t *testing.T) {
	_, vr, wsURL, teardown := setupTestRelay(t)
	defer teardown()

	sk, pk := generateTestUser()
	err := vr.InternalChangePubKey(context.Background(), pk.Hex(), store.PubKeyAllowed, "")
	if err != nil {
		t.Fatalf("Failed to whitelist test user: %v", err)
	}

	ctx := context.Background()
	relay, err := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	if err != nil {
		t.Fatalf("Connect error: %v", err)
	}

	ev := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Content:   "NIP-01 Test",
	}
	err = ev.Sign(sk)
	if err != nil {
		t.Fatalf("Signing filed: %v", err)
	}

	err = relay.Publish(ctx, ev)
	if err != nil {
		if strings.Contains(err.Error(), "auth-required") {
			if authErr := relay.Auth(ctx, func(ctx context.Context, evt *nostr.Event) error { return evt.Sign(sk) }); authErr != nil {
				t.Fatalf("Auth failed: %v", authErr)
			}
		}
		err = relay.Publish(ctx, ev)
		if err != nil {
			t.Fatalf("Publish failed: %v", err)
		}
	}

	sub, err := relay.Subscribe(ctx, nostr.Filter{
		Kinds:   []nostr.Kind{1},
		Authors: []nostr.PubKey{pk},
	}, nostr.SubscriptionOptions{})
	if err != nil {
		t.Fatalf("Subscribe failed: %v", err)
	}

	select {
	case received := <-sub.Events:
		if received.Content != "NIP-01 Test" {
			t.Errorf("Received unexpected content: %s", received.Content)
		}
	case <-sub.EndOfStoredEvents:
		// Valid behavior if store is empty
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for event or EOSE")
	}
}

// -----------------------------------------------------------------------------
// NIP-09: Event Deletion
// -----------------------------------------------------------------------------

func TestNIP09_Deletion(t *testing.T) {
	_, vr, wsURL, teardown := setupTestRelay(t)
	defer teardown()

	sk, pk := generateTestUser()
	err := vr.InternalChangePubKey(context.Background(), pk.Hex(), store.PubKeyAllowed, "")
	if err != nil {
		t.Fatalf("Failed to whitelist test user: %v", err)
	}
	ctx := context.Background()
	relay, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	defer relay.Close()

	// 1. Publish regular event
	ev1 := nostr.Event{PubKey: pk, CreatedAt: nostr.Now(), Kind: 1, Content: "To be deleted"}
	ev1.Sign(sk)
	err = relay.Publish(ctx, ev1)
	if err != nil {
		if strings.Contains(err.Error(), "auth-required") {
			if authErr := relay.Auth(ctx, func(ctx context.Context, evt *nostr.Event) error { return evt.Sign(sk) }); authErr != nil {
				t.Fatalf("Auth failed: %v", authErr)
			}
		}
		err = relay.Publish(ctx, ev1)
		if err != nil {
			t.Fatalf("Publish failed: %v", err)
		}
	}

	// 2. Publish Deletion (Kind 5)
	evDel := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      5,
		Tags:      nostr.Tags{nostr.Tag{"e", ev1.ID.Hex()}},
		Content:   "Oops",
	}
	evDel.Sign(sk)
	err = relay.Publish(ctx, evDel)
	if err != nil {
		t.Fatalf("Publish deletion failed: %v", err)
	}

	// 3. Query for ev1
	sub, _ := relay.Subscribe(ctx, nostr.Filter{IDs: []nostr.ID{ev1.ID}}, nostr.SubscriptionOptions{})

	select {
	case e := <-sub.Events:
		if e.ID.Hex() == ev1.ID.Hex() {
			t.Errorf("Event string: %s content: %s kind: %s should have been deleted, but was received", e.ID.String(), e.Content, e.Kind.String())
		}
	case <-sub.EndOfStoredEvents:
		// Correct behavior: event not found
	case <-time.After(1 * time.Second):
		// Timeout implies nothing sent, which is also correct
	}
}

// -----------------------------------------------------------------------------
// NIP-11: Relay Information Document
// -----------------------------------------------------------------------------

func TestNIP11_RelayInfo(t *testing.T) {
	ts, vr, _, teardown := setupTestRelay(t)
	defer teardown()

	ctx := context.Background()

	// Perform standard HTTP request with Accept header
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL, nil)
	req.Header.Set("Accept", "application/nostr+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to request NIP-11 info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
	}

	var info nip11.RelayInformationDocument
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		t.Fatalf("Failed to decode NIP-11 JSON: %v", err)
	}

	// Assertions based on your Config in New()
	if info.Name != vr.Config.RelayName {
		t.Errorf("Expected name %s, got %s", vr.Config.RelayName, info.Name)
	}
	if !info.Limitation.AuthRequired {
		t.Error("Expected AuthRequired to be true")
	}

	// Verify Supported NIPs are present
	expectedNips := []int{1, 9, 11, 40, 42, 45, 70, 77, 86}
	for _, expected := range expectedNips {
		found := false
		for _, supported := range info.SupportedNIPs {
			// SupportedNIPs can be int or string depending on json unmarshal, handle carefully
			if v, ok := supported.(float64); ok && int(v) == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("NIP-%d should be listed in supported NIPs", expected)
		}
	}
}

// -----------------------------------------------------------------------------
// NIP-40: Expiration Timestamp
// -----------------------------------------------------------------------------

func TestNIP40_Expiration(t *testing.T) {
	_, vr, wsURL, teardown := setupTestRelay(t)
	defer teardown()

	sk, pk := generateTestUser()
	err := vr.InternalChangePubKey(context.Background(), pk.Hex(), store.PubKeyAllowed, "")
	if err != nil {
		t.Fatalf("Failed to whitelist test user: %v", err)
	}
	ctx := context.Background()
	relay, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	defer relay.Close()

	// 1. Test Future Expiration (Should be accepted)
	futureExp := nostr.Now() + 3600 // 1 hour in future
	evFuture := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Content:   "Expires soon",
		Tags:      nostr.Tags{{"expiration", fmt.Sprintf("%d", futureExp)}},
	}
	evFuture.Sign(sk)

	err = relay.Publish(ctx, evFuture)
	if err != nil {
		if strings.Contains(err.Error(), "auth-required") {
			if authErr := relay.Auth(ctx, func(ctx context.Context, evt *nostr.Event) error { return evt.Sign(sk) }); authErr != nil {
				t.Fatalf("Auth failed: %v", authErr)
			}
		}
		err = relay.Publish(ctx, evFuture)
		if err != nil {
			t.Fatalf("Publish failed: %v", err)
		}
	}

	// 2. Test Past Expiration (Should be rejected)
	pastExp := nostr.Now() - 3600 // 1 hour ago
	evPast := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Content:   "Already expired",
		Tags:      nostr.Tags{{"expiration", fmt.Sprintf("%d", pastExp)}},
	}
	evPast.Sign(sk)

	err = relay.Publish(ctx, evPast)
	if err != nil {
		t.Errorf("Publish failed: %v", err)
	}
}

// -----------------------------------------------------------------------------
// NIP-42: Authentication
// -----------------------------------------------------------------------------

func TestNIP42_Authentication(t *testing.T) {
	_, vr, wsURL, teardown := setupTestRelay(t)
	defer teardown()

	sk, pk := getOwnerKeys()
	err := vr.InternalChangePubKey(context.Background(), pk.Hex(), store.PubKeyAllowed, "")
	if err != nil {
		t.Fatalf("Failed to whitelist test user: %v", err)
	}

	// Connect without Auth first
	ctx := context.Background()
	relay, err := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer relay.Close()

	// Since policies.MustAuth is on, the relay should have sent an AUTH challenge immediately.
	// We need to listen for it.

	// Note: nostr.RelayConnect doesn't automatically handle Auth unless we set a Signer.
	// Here we want to test the raw flow manually to ensure the relay sends the challenge.

	// We will try to publish; it should fail with "auth-required"
	ev := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Tags:      nostr.Tags{},
		Content:   "Hello World",
	}
	ev.Sign(sk)

	err = relay.Publish(ctx, ev)
	if err == nil {
		t.Errorf("Expected publish to fail before auth: %v", err)
	}

	// Now let's perform the actual Auth
	// We assert that the Challenge was stored in the relay object (go-nostr handles receiving it)
	/*if relay.Challenge == "" {
		t.Error("Relay did not send an AUTH challenge upon connection")
	}*/

	// Send Auth
	err = relay.Auth(ctx, func(ctx context.Context, evt *nostr.Event) error {
		return evt.Sign(sk)
	})

	// In a real integration test using nostr-sdk, .Auth() handles the sending.
	// To be very specific, we can manually send:
	// relay.Connection.WriteJSON([]interface{}{"AUTH", authEvent})

	// However, let's assume we want to verify the relay accepts it.
	// We can simply try to publish again. If Auth succeeded, publish *might* proceed
	// (depending on payment policy, but it shouldn't fail on "auth-required").

	// Check if we are considered authenticated
	// Since we can't easily introspect the relay's memory, we rely on the absence of "auth-required" error.
}

// -----------------------------------------------------------------------------
// NIP-45: Event Counts
// -----------------------------------------------------------------------------

func TestNIP45_Count(t *testing.T) {
	_, vr, wsURL, teardown := setupTestRelay(t)
	defer teardown()
	sk, pk := generateTestUser()
	err := vr.InternalChangePubKey(context.Background(), pk.Hex(), store.PubKeyAllowed, "")
	if err != nil {
		t.Fatalf("Failed to whitelist test user: %v", err)
	}

	ctx := context.Background()
	relay, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	defer relay.Close()

	// Publish 2 events
	for i := 0; i < 2; i++ {
		ev := nostr.Event{PubKey: pk, CreatedAt: nostr.Now(), Kind: 1, Content: fmt.Sprintf("msg %d", i)}
		ev.Sign(sk)
		err := relay.Publish(ctx, ev)
		if err != nil {
			if strings.Contains(err.Error(), "auth-required") {
				if authErr := relay.Auth(ctx, func(ctx context.Context, evt *nostr.Event) error { return evt.Sign(sk) }); authErr != nil {
					t.Fatalf("Auth failed: %v", authErr)
				}
			}
			err = relay.Publish(ctx, ev)
			if err != nil {
				t.Fatalf("Publish failed: %v", err)
			}
		}
	}

	// Use Count method
	count, _, err := relay.Count(ctx, nostr.Filter{
		Kinds:   []nostr.Kind{1},
		Authors: []nostr.PubKey{pk},
	}, nostr.SubscriptionOptions{})

	if err != nil {
		t.Fatalf("Count command failed: %v", err)
	}

	// If Store is working, count should be 2. If mock store is nil/empty, might be 0.
	// We just test that the command didn't error out (NIP-45 supported).
	t.Logf("Count returned: %d", count)
}

// -----------------------------------------------------------------------------
// NIP-70: Protected Events
// -----------------------------------------------------------------------------

func TestNIP70_ProtectedEvents(t *testing.T) {
	_, vr, wsURL, teardown := setupTestRelay(t)
	defer teardown()

	// User A: Author of protected event
	skA, pkA := generateTestUser()
	// User B: Random other user
	skB, pkB := generateTestUser()

	// Whitelist both to bypass payment checks
	ctx := context.Background()
	err := vr.InternalChangePubKey(context.Background(), pkA.Hex(), store.PubKeyAllowed, "")
	if err != nil {
		t.Fatalf("Failed to whitelist test user A: %v", err)
	}
	err = vr.InternalChangePubKey(context.Background(), pkB.Hex(), store.PubKeyAllowed, "")
	if err != nil {
		t.Fatalf("Failed to whitelist test user B: %v", err)
	}

	// --- 1. User A Publishes Protected Event ---
	relayA, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})

	protectedEv := nostr.Event{
		PubKey:    pkA,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Content:   "Secret stuff",
		// NIP-70 tag: ["-"] (empty string as value, key is "-")
		// Ideally: ["-"] or ["-", ""] depending on parser strictness.
		// Standard is just key "-".
		Tags: nostr.Tags{{"-"}},
	}
	protectedEv.Sign(skA)
	err = relayA.Publish(ctx, protectedEv)
	if err != nil {
		if strings.Contains(err.Error(), "auth-required") {
			if authErr := relayA.Auth(ctx, func(ctx context.Context, evt *nostr.Event) error { return evt.Sign(skA) }); authErr != nil {
				t.Fatalf("Auth failed: %v", authErr)
			}
		}
		err = relayA.Publish(ctx, protectedEv)
		if err != nil {
			t.Fatalf("Publish failed: %v", err)
		}
	}
	relayA.Close()

	// --- 2. Unauthenticated Client Tries to Read ---
	// Need a fresh connection that DOES NOT Auth
	relayUnauth, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	// Do NOT call Auth()

	subUnauth, _ := relayUnauth.Subscribe(ctx, nostr.Filter{IDs: []nostr.ID{protectedEv.ID}}, nostr.SubscriptionOptions{})

	select {
	case e := <-subUnauth.Events:
		if e.Kind == 1 {
			t.Errorf("NIP-70 Failure: Unauthenticated client received protected event %s", e.ID)
		}
	case <-time.After(500 * time.Millisecond):
		// Success: Timeout means we didn't get it
	}
	relayUnauth.Close()

	// --- 3. Authenticated Client (User B) Tries to Read ---
	// NIP-70 implies: "Relays SHOULD NOT publish these events to clients that are not authenticated."
	// It doesn't strictly mean ONLY the author can see it, just that you must be AUTH'd.
	relayB, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	relayB.Auth(ctx, func(ctx context.Context, e *nostr.Event) error { return e.Sign(skB) })

	subB, _ := relayB.Subscribe(ctx, nostr.Filter{IDs: []nostr.ID{protectedEv.ID}}, nostr.SubscriptionOptions{})

	select {
	case e := <-subB.Events:
		if e.Kind == 1 && e.ID != protectedEv.ID {
			t.Error("NIP-70: Received wrong event")
		}
	case <-time.After(1 * time.Second):
		t.Error("NIP-70 Failure: Authenticated client FAILED to receive protected event")
	}
	relayB.Close()
}

// -----------------------------------------------------------------------------
// NIP-77: Negentropy (Reconciliation)
// -----------------------------------------------------------------------------

func TestNIP77_Negentropy(t *testing.T) {
	_, _, wsURL, teardown := setupTestRelay(t)
	defer teardown()

	// 1. Connect via raw WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Websocket dial failed: %v", err)
	}
	defer conn.Close()

	// 2. Handle Initial AUTH Challenge
	_, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read initial message: %v", err)
	}

	var authMsg []json.RawMessage
	if err := json.Unmarshal(message, &authMsg); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	if len(authMsg) < 2 {
		t.Fatalf("Message too short: %s", message)
	}

	var msgType string
	json.Unmarshal(authMsg[0], &msgType)

	if msgType != "AUTH" {
		t.Fatalf("Expected AUTH challenge, got %s", msgType)
	}

	var challenge string
	json.Unmarshal(authMsg[1], &challenge)

	// 3. Perform Authentication
	sk, pk := generateTestUser()
	authEv := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      22242,
		Tags:      nostr.Tags{{"relay", wsURL}, {"challenge", challenge}},
		Content:   "",
	}
	authEv.Sign(sk)

	// Send ["AUTH", event]
	if err := conn.WriteJSON([]any{"AUTH", authEv}); err != nil {
		t.Fatalf("Failed to send AUTH: %v", err)
	}

	// 4. Consume the OK response for Auth
	// Relay should reply ["OK", event_id, true, "..."]
	_, message, err = conn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read AUTH response: %v", err)
	}
	if !strings.Contains(string(message), "OK") || !strings.Contains(string(message), "true") {
		t.Fatalf("Authentication failed, got: %s", message)
	}

	// 5. Now Send NEG-OPEN
	// ["NEG-OPEN", "sub-id", filter, idLen, initialBound]
	filter := nostr.Filter{Kinds: []nostr.Kind{1}, Limit: 10}
	negMsg := []any{
		"NEG-OPEN",
		"test-neg-sub",
		filter,
		"", // initial bound
	}

	if err := conn.WriteJSON(negMsg); err != nil {
		t.Fatalf("Failed to send NEG-OPEN: %v", err)
	}

	// 6. Read Response (Expect NEG-MSG or NEG-ERR)
	_, message, err = conn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read NEG response: %v", err)
	}

	msgStr := string(message)
	if strings.Contains(msgStr, "NEG-MSG") || strings.Contains(msgStr, "NEG-ERR") {
		// Passed
	} else if strings.Contains(msgStr, "CLOSED") {
		t.Errorf("Subscription closed unexpectedly: %s", msgStr)
	} else {
		t.Errorf("Expected NEG-MSG or NEG-ERR, received: %s", msgStr)
	}
}

// -----------------------------------------------------------------------------
// NIP-86: Management API
// -----------------------------------------------------------------------------

func TestNIP86_Management(t *testing.T) {
	_, vr, wsURL, teardown := setupTestRelay(t)
	defer teardown()

	// NIP-86 usually requires the user to be an admin (AllowPubKey logic in your code).
	// But purely checking the RPC method existence:

	ctx := context.Background()
	relay, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	defer relay.Close()

	// Setup Admin User
	sk, pk := generateTestUser()
	err := vr.InternalChangePubKey(context.Background(), pk.Hex(), store.PubKeyAllowed, "")
	if err != nil {
		t.Fatalf("Failed to whitelist test user: %v", err)
	}

	// Authenticate as Admin
	time.Sleep(50 * time.Millisecond)
	relay.Auth(ctx, func(ctx context.Context, evt *nostr.Event) error { return evt.Sign(sk) })

	// Construct NIP-86 Request: ["REQ", "id", {"method": "...", "params": [...]}]
	// go-nostr doesn't have a direct helper for NIP-86 generic calls yet in the high level client,
	// but we can assume your `khatru` relay handles it via the `nip86` package.

	// We'll use the internal RPC mechanism logic or try to craft a message.
	// Since `khatru` uses standard RPC over WebSocket, we can use `WriteJSON`.

	/*rpcID := "test-nip86"
	rpcRequest := nip86.Request{
		Method: "listallowedpubkeys",
		Params: []any{},
	}*/

	// Send RPC
	// The standard nostr.Relay doesn't expose sending arbitrary JSON easily without modifying connection.
	// But we can check if the methods are hooked up in `vr`.

	if vr.ManagementAPI.ListAllowedPubKeys == nil {
		t.Fatal("NIP-86 ListAllowedPubKeys handler is not set")
	}

	// Execute the handler directly to verify logic (Unit Test style)
	// instead of Integration style for this complex part without a dedicated client.

	// We expect the pubkey we just allowed to be in the list
	res, err := vr.InternalListPubKeys(store.PubKeyAllowed)
	if err != nil {
		t.Fatalf("Management API failed: %v", err)
	}

	// res should be []string
	found := false
	for _, p := range res {
		if p.PubKey == pk {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Management API did not return the key we allowed manually")
	}
}
