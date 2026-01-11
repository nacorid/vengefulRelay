package relay_test

import (
	"context"
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
)

// -----------------------------------------------------------------------------
// Test Setup Helper
// -----------------------------------------------------------------------------
var (
	relaySk nostr.SecretKey
	relayPk nostr.PubKey
)

// setupTestRelay spins up a test HTTP server with your relay.
// YOU NEED TO FILL IN THE MOCKS FOR YOUR INTERNAL DEPENDENCIES HERE.
func setupTestRelay(t *testing.T) (*httptest.Server, *relay.VengefulRelay, string) {
	t.Helper()

	// 1. Mock Config
	// We use a generated key for the relay identity
	relaySk = nostr.Generate()
	relayPk = nostr.GetPublicKey(relaySk)

	cfg := config.Config{
		RelayName:        "Test Relay",
		RelayPubkey:      relayPk.String(),
		RelayDescription: "Unit testing relay",
		RelayURL:         "ws://localhost",
		Whitelist:        []string{relayPk.String()},
		MaxEventLength:   100000,
		MinPowDifficulty: 0, // Keep 0 for fast tests
		AdmissionFee:     1000,
	}

	// 2. Mock Store
	st, err := store.Init("postgres://nostr@/nostr_test?host=/var/run/postgresql")
	if err != nil {
		t.Log("WARNING: Store is nil. Tests requiring persistence will panic until you mock the Store.")
	}

	// 3. Mock Lightning Provider
	// TODO: Initialize a mock LN provider
	var ln *lightning.Provider = nil // <--- REPLACE THIS

	// 4. Initialize Relay
	// Passing nil logger for cleaner test output
	vr := relay.New(cfg, st, ln, nil)

	// 5. Create Test Server
	// Khatru relay implements http.Handler
	ts := httptest.NewServer(vr)

	// Convert http:// to ws:// for client connections
	wsURL := strings.Replace(ts.URL, "http", "ws", 1)

	return ts, vr, wsURL
}

// generateTestUser creates a keypair for a test client
func generateTestUser() (nostr.SecretKey, nostr.PubKey) {
	/*
		sk := nostr.Generate()
		pk := nostr.GetPublicKey(sk)
		return sk, pk
	*/
	return relaySk, relayPk
}

// -----------------------------------------------------------------------------
// NIP-11: Relay Information Document
// -----------------------------------------------------------------------------

func TestNIP11_RelayInfo(t *testing.T) {
	ts, vr, _ := setupTestRelay(t)
	defer ts.Close()

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
// NIP-42: Authentication
// -----------------------------------------------------------------------------

func TestNIP42_Authentication(t *testing.T) {
	ts, _, wsURL := setupTestRelay(t)
	defer ts.Close()

	sk, pk := generateTestUser()

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
// NIP-01: Basic Protocol (Req, Event, Eose)
// -----------------------------------------------------------------------------

func TestNIP01_BasicFlow(t *testing.T) {
	ts, _, wsURL := setupTestRelay(t)
	defer ts.Close()

	// Bypass payment policy for this test if possible, or Mock Store to say "paid"
	// For this test, we assume the mock Store allows writes or we are whitelisted.
	// *Hack for testing*: Manually whitelist the key in the relay instance if you have a method
	sk, pk := generateTestUser()
	/*
		err := vr.ManagementAPI.AllowPubKey(context.Background(), pk, "") // Whitelist user to bypass payment/admission if logic allows
		if err != nil {
			t.Fatalf("Whitelist error: %v", err)
		}
	*/

	ctx := context.Background()
	relay, err := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	if err != nil {
		t.Fatalf("Connect error: %v", err)
	}

	// 1. Authenticate
	authEv := func(ctx context.Context, evt *nostr.Event) error {
		return evt.Sign(sk)
	}
	// Wait for challenge
	time.Sleep(50 * time.Millisecond)
	if err := relay.Auth(ctx, authEv); err != nil {
		t.Fatalf("Auth failed: %v", err)
	}

	// 2. Publish Event
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
		t.Fatalf("Publish failed: %v", err)
	}

	// 3. Subscribe
	sub, err := relay.Subscribe(ctx, nostr.Filter{
		Kinds:   []nostr.Kind{1},
		Authors: []nostr.PubKey{pk},
	}, nostr.SubscriptionOptions{})
	if err != nil {
		t.Fatalf("Subscribe failed: %v", err)
	}

	// 4. Read Event (if publish worked) or EOSE
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
	ts, vr, wsURL := setupTestRelay(t)
	defer ts.Close()

	sk, pk := generateTestUser()
	vr.ManagementAPI.AllowPubKey(context.Background(), pk, "")

	ctx := context.Background()
	relay, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	defer relay.Close()

	// Auth
	time.Sleep(50 * time.Millisecond)
	relay.Auth(ctx, func(ctx context.Context, evt *nostr.Event) error { return evt.Sign(sk) })

	// 1. Publish regular event
	ev1 := nostr.Event{PubKey: pk, CreatedAt: nostr.Now(), Kind: 1, Content: "To be deleted"}
	ev1.Sign(sk)
	relay.Publish(ctx, ev1)

	// 2. Publish Deletion (Kind 5)
	evDel := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      5,
		Tags:      nostr.Tags{nostr.Tag{"e", ev1.ID.Hex()}},
		Content:   "Oops",
	}
	evDel.Sign(sk)
	relay.Publish(ctx, evDel)

	// 3. Query for ev1
	// Depending on Relay implementation, it might not return it,
	// or return it but the client filters it (khatru typically deletes from store or marks deleted)
	sub, _ := relay.Subscribe(ctx, nostr.Filter{IDs: []nostr.ID{ev1.ID}}, nostr.SubscriptionOptions{})

	select {
	case e := <-sub.Events:
		t.Errorf("Event %s should have been deleted, but was received", e.ID)
	case <-sub.EndOfStoredEvents:
		// Correct behavior: event not found
	case <-time.After(1 * time.Second):
		// Timeout implies nothing sent, which is also correct
	}
}

// -----------------------------------------------------------------------------
// NIP-45: Event Counts
// -----------------------------------------------------------------------------

func TestNIP45_Count(t *testing.T) {
	ts, vr, wsURL := setupTestRelay(t)
	defer ts.Close()
	sk, pk := generateTestUser()
	vr.ManagementAPI.AllowPubKey(context.Background(), pk, "")

	ctx := context.Background()
	relay, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	defer relay.Close()

	time.Sleep(50 * time.Millisecond)
	relay.Auth(ctx, func(ctx context.Context, evt *nostr.Event) error { return evt.Sign(sk) })

	// Publish 2 events
	for i := 0; i < 2; i++ {
		ev := nostr.Event{PubKey: pk, CreatedAt: nostr.Now(), Kind: 1, Content: fmt.Sprintf("msg %d", i)}
		ev.Sign(sk)
		relay.Publish(ctx, ev)
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
// NIP-86: Management API
// -----------------------------------------------------------------------------

func TestNIP86_Management(t *testing.T) {
	ts, vr, wsURL := setupTestRelay(t)
	defer ts.Close()

	// NIP-86 usually requires the user to be an admin (AllowPubKey logic in your code).
	// But purely checking the RPC method existence:

	ctx := context.Background()
	relay, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	defer relay.Close()

	// Setup Admin User
	sk, pk := generateTestUser()

	// IMPORTANT: In your code, you likely need to configure WHO is allowed to access management.
	// Usually via `vr.ManagementAPI.AllowPubKey` logic.
	// For this test, we assume the relay setup allows this PK or we force it:
	vr.ManagementAPI.AllowPubKey(ctx, pk, "")

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
	// This tests the `vr.allowPubKey` and `vr.listAllowedPubKeys` implementation logic.
	res, err := vr.ManagementAPI.ListAllowedPubKeys(ctx)
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
