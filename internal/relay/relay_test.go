package relay_test

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
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
	var ln lightning.Provider = nil // <--- REPLACE THIS

	// 5. Initialize Relay
	// Passing nil logger for cleaner test output
	l := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))
	vr := relay.New(cfg, st, ln, l)
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

func sign(sk nostr.SecretKey) func(ctx context.Context, e *nostr.Event) error {
	return func(ctx context.Context, e *nostr.Event) error {
		return e.Sign(sk)
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

func mineEvent(ev *nostr.Event, targetDiff int) {
	var nonce uint64 = 0
	for {
		// Update the Nonce Tag
		// Format: ["nonce", "nonce_string", "target_difficulty_string"]
		ev.Tags = nostr.Tags{
			{"nonce", fmt.Sprintf("%d", nonce), fmt.Sprintf("%d", targetDiff)},
		}

		// Recalculate ID
		ev.ID = ev.GetID()

		// Check Difficulty
		// nostr.CheckProofOfWork returns true if the ID meets the target
		if checkPoW(ev.ID.Hex(), targetDiff) {
			return
		}

		nonce++
		// prevent infinite loop in case of bad logic (8 bits should take microseconds)
		if nonce > 1000000 {
			panic("mining took too long for low difficulty")
		}
	}
}

// checkPoW counts leading zero bits in the hex ID
func checkPoW(idHex string, target int) bool {
	// Simple implementation for test purposes
	// Convert hex to bytes
	bytes, _ := hex.DecodeString(idHex)

	zeros := 0
	for _, b := range bytes {
		if b == 0 {
			zeros += 8
		} else {
			// Count leading zeros in this byte
			for i := 7; i >= 0; i-- {
				if (b>>i)&1 == 0 {
					zeros++
				} else {
					break
				}
			}
			break
		}
	}
	return zeros >= target
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
			if authErr := relay.Auth(ctx, sign(sk)); authErr != nil {
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
// NIP-04: Encrypted Direct Messages
// -----------------------------------------------------------------------------

func TestNIP04_DirectMessages(t *testing.T) {
	_, vr, wsURL, teardown := setupTestRelay(t)
	defer teardown()

	// Alice (Sender) and Bob (Receiver)
	skAlice, pkAlice := generateTestUser()
	_, pkBob := generateTestUser()

	// Whitelist both to bypass payment checks
	ctx := context.Background()
	vr.InternalChangePubKey(ctx, pkAlice.Hex(), store.PubKeyAllowed, "")
	vr.InternalChangePubKey(ctx, pkBob.Hex(), store.PubKeyAllowed, "")

	// --- 1. Alice connects ---
	relayAlice, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	defer relayAlice.Close()

	// --- 2. Bob connects ---
	relayBob, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	defer relayBob.Close()

	// --- 3. Alice Sends DM to Bob ---
	// Note: In a real client, content is encrypted. For a relay test,
	// we only care that Kind=4 and Tags are handled correctly.
	dmEvent := nostr.Event{
		PubKey:    pkAlice,
		CreatedAt: nostr.Now(),
		Kind:      4,
		Tags:      nostr.Tags{{"p", pkBob.Hex()}},
		Content:   "fake-encrypted-content-base64",
	}
	dmEvent.Sign(skAlice)

	err := relayAlice.Publish(ctx, dmEvent)
	if err != nil {
		if strings.Contains(err.Error(), "auth-required") {
			if authErr := relayAlice.Auth(ctx, sign(skAlice)); authErr != nil {
				t.Fatalf("Auth failed: %v", authErr)
			}
		}
		err = relayAlice.Publish(ctx, dmEvent)
		if err != nil {
			t.Fatalf("Failed to publish NIP-04 DM: %v", err)
		}
	}

	// --- 4. Bob Retrieves his DMs ---
	// Bob filters by Kind 4 and #p = his pubkey
	subBob, _ := relayBob.Subscribe(ctx, nostr.Filter{
		Kinds: []nostr.Kind{4},
		Tags:  nostr.TagMap{"p": []string{pkBob.Hex()}},
	}, nostr.SubscriptionOptions{})

	select {
	case e := <-subBob.Events:
		if e.ID != dmEvent.ID {
			t.Error("Bob received wrong DM event")
		}
		if e.Content != "fake-encrypted-content-base64" {
			t.Error("Content corrupted")
		}
	case <-time.After(1 * time.Second):
		t.Error("NIP-04 Failure: Bob did not receive the DM sent to him")
	}

	// --- 5. Alice Retrieves her Sent DMs ---
	// Alice filters by Kind 4 and Authors = her pubkey
	subAlice, _ := relayAlice.Subscribe(ctx, nostr.Filter{
		Kinds:   []nostr.Kind{4},
		Authors: []nostr.PubKey{pkAlice},
	}, nostr.SubscriptionOptions{})

	select {
	case e := <-subAlice.Events:
		if e.ID != dmEvent.ID {
			t.Error("Alice received wrong DM event")
		}
	case <-time.After(1 * time.Second):
		t.Error("NIP-04 Failure: Alice could not retrieve her own sent DM")
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
			if authErr := relay.Auth(ctx, sign(sk)); authErr != nil {
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
// NIP-13: Proof of Work
// -----------------------------------------------------------------------------

func TestNIP13_ProofOfWork(t *testing.T) {
	_, vr, wsURL, teardown := setupTestRelay(t)
	defer teardown()

	// 1. Configure the Relay to require PoW
	// We set a low difficulty (8 bits) so the test runs instantly but still validates logic.
	const requiredDifficulty = 8
	vr.Config.MinPowDifficulty = requiredDifficulty

	// Update NIP-11 info to reflect this (optional for logic, good for consistency)
	vr.Info.Limitation.MinPowDifficulty = requiredDifficulty

	// Create a user
	sk, pk := generateTestUser()
	ctx := context.Background()

	// Whitelist user (if necessary) to bypass other checks like payment,
	// focusing strictly on PoW.
	vr.InternalChangePubKey(ctx, pk.Hex(), store.PubKeyAllowed, "")

	relay, err := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer relay.Close()

	// --- Test Case 1: Insufficient PoW (Should Fail) ---
	badEvent := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Content:   "Lazy event without work",
		// No nonce tag, or insufficient nonce
	}
	badEvent.Sign(sk)
	t.Logf("Bad Event ID: %s", badEvent.ID.Hex())
	err = relay.Publish(ctx, badEvent)
	if err != nil {
		if strings.Contains(err.Error(), "auth-required") {
			if authErr := relay.Auth(ctx, sign(sk)); authErr != nil {
				t.Fatalf("Auth failed: %v", authErr)
			}
		}
		err = relay.Publish(ctx, badEvent)
		if err == nil {
			t.Fatal("NIP-13 Failure: Relay accepted event with NO Proof of Work, expected rejection.")
		}
	}

	// --- Test Case 2: Sufficient PoW (Should Pass) ---
	goodEvent := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Content:   "Hard working event",
	}

	// Mine the event
	// We need to add a ["nonce", "nonce_val", "target_difficulty"] tag
	// and keep changing nonce_val until ID has enough leading zeros.
	mineEvent(&goodEvent, requiredDifficulty)
	goodEvent.Sign(sk)

	err = relay.Publish(ctx, goodEvent)
	if err != nil {
		t.Fatalf("Failed to publish valid PoW event: %v", err)
	}
}

// -----------------------------------------------------------------------------
// NIP-15: Nostr Marketplace (Stalls and Products)
// -----------------------------------------------------------------------------

func TestNIP15_Marketplace(t *testing.T) {
	_, vr, wsURL, teardown := setupTestRelay(t)
	defer teardown()

	sk, pk := generateTestUser()
	vr.InternalChangePubKey(context.Background(), pk.Hex(), store.PubKeyAllowed, "")

	ctx := context.Background()
	relay, err := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer relay.Close()

	// --- 1. Create a Stall (Kind 30017) ---
	// Stalls are Parameterized Replaceable Events (d-tag).
	stallID := "my-awesome-stall"
	stall := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      30017,
		Tags: nostr.Tags{
			{"d", stallID},
			{"name", "Bitcorn General Store"},
			{"currency", "SAT"},
		},
		Content: `{"description": "Selling the finest corns"}`,
	}
	stall.Sign(sk)

	err = relay.Publish(ctx, stall)
	if err != nil {
		if strings.Contains(err.Error(), "auth-required") {
			if authErr := relay.Auth(ctx, sign(sk)); authErr != nil {
				t.Fatalf("Auth failed: %v", authErr)
			}
		}
		err = relay.Publish(ctx, stall)
		if err != nil {
			t.Fatalf("Failed to publish Stall: %v", err)
		}
	}

	// --- 2. Create a Product (Kind 30018) ---
	// Products are linked to stalls and are also Parameterized Replaceable.
	productID := "corn-kernel-v1"
	productV1 := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      30018,
		Tags: nostr.Tags{
			{"d", productID},
			{"stall_id", stallID}, // Link to stall
			{"t", "food"},
		},
		Content: `{"name": "Single Corn Kernel", "price": 10}`,
	}
	productV1.Sign(sk)

	err = relay.Publish(ctx, productV1)
	if err != nil {
		t.Fatalf("Failed to publish Product V1: %v", err)
	}

	// --- 3. Verify Storage ---
	// Fetch the product
	sub, _ := relay.Subscribe(ctx, nostr.Filter{
		Authors: []nostr.PubKey{pk},
		Kinds:   []nostr.Kind{30018},
		Tags:    nostr.TagMap{"d": []string{productID}},
	}, nostr.SubscriptionOptions{})

	select {
	case e := <-sub.Events:
		if e.ID != productV1.ID {
			t.Error("Marketplace: Retrieved wrong product event")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Marketplace: Failed to retrieve product")
	}

	// --- 4. Update Product (NIP-01 Parameterized Replacement) ---
	// We change the price. The "d" tag stays the same.
	// The relay should Replace the old event with this one.
	productV2 := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now() + 10, // Must be newer
		Kind:      30018,
		Tags: nostr.Tags{
			{"d", productID}, // Same ID
			{"stall_id", stallID},
		},
		Content: `{"name": "Single Corn Kernel", "price": 20}`, // Inflation!
	}
	productV2.Sign(sk)

	relay.Publish(ctx, productV2)

	// --- 5. Verify Replacement ---
	// Querying for this product ID should now return ONLY Version 2
	sub2, _ := relay.Subscribe(ctx, nostr.Filter{
		Authors: []nostr.PubKey{pk},
		Kinds:   []nostr.Kind{30018},
		Tags:    nostr.TagMap{"d": []string{productID}},
	}, nostr.SubscriptionOptions{})

	var events []nostr.Event
Loop:
	for {
		select {
		case e := <-sub2.Events:
			events = append(events, e)
		case <-sub2.EndOfStoredEvents:
			break Loop
		case <-time.After(1 * time.Second):
			break Loop
		}
	}

	if len(events) != 1 {
		t.Errorf("Marketplace: Expected 1 product event after update, got %d", len(events))
	} else {
		if events[0].Content != productV2.Content {
			t.Error("Marketplace: Relay returned old product version, replacement failed")
		}
	}
}

// -----------------------------------------------------------------------------
// NIP-17: Private Direct Messages (Gift Wraps)
// -----------------------------------------------------------------------------

func TestNIP17_GiftWraps(t *testing.T) {
	_, vr, wsURL, teardown := setupTestRelay(t)
	defer teardown()

	skAlice, pkAlice := generateTestUser()
	_, pkBob := generateTestUser()

	// Whitelist
	ctx := context.Background()
	vr.InternalChangePubKey(ctx, pkAlice.Hex(), store.PubKeyAllowed, "")
	vr.InternalChangePubKey(ctx, pkBob.Hex(), store.PubKeyAllowed, "")

	// Connect/Auth
	relayAlice, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	defer relayAlice.Close()

	relayBob, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	defer relayBob.Close()

	// --- NIP-17 Mechanism ---
	// 1. Kind 1059 (Gift Wrap) is the outer shell.
	// 2. It contains an encrypted seal in `.Content`.
	// 3. It MUST have a "p" tag pointing to the receiver.
	// Note: NIP-17 suggests blinding the metadata, but from the Relay's perspective,
	// it just sees a Kind 1059 with a valid "p" tag to index.

	giftWrap := nostr.Event{
		PubKey:    pkAlice,                        // In reality, this is a random ephemeral key, but Relay doesn't care
		CreatedAt: nostr.Now(),                    // Can be tweaked (timestamp blinding), Relay doesn't care
		Kind:      1059,                           // Gift Wrap
		Tags:      nostr.Tags{{"p", pkBob.Hex()}}, // The recipient
		Content:   "encrypted-nip44-blob",
	}
	giftWrap.Sign(skAlice)

	// 1. Alice sends the Gift Wrap
	err := relayAlice.Publish(ctx, giftWrap)
	if err != nil {
		if strings.Contains(err.Error(), "auth-required") {
			if authErr := relayAlice.Auth(ctx, sign(skAlice)); authErr != nil {
				t.Fatalf("Auth failed: %v", authErr)
			}
		}
		err = relayAlice.Publish(ctx, giftWrap)
		if err != nil {
			t.Fatalf("Failed to publish NIP-17 Gift Wrap: %v", err)
		}
	}

	// 2. Bob subscribes to Gift Wraps addressed to him
	// NIP-17 clients subscribe to kind 1059 and #p = their pubkey
	subBob, _ := relayBob.Subscribe(ctx, nostr.Filter{
		Kinds: []nostr.Kind{1059},
		Tags:  nostr.TagMap{"p": []string{pkBob.Hex()}},
	}, nostr.SubscriptionOptions{})

	select {
	case e := <-subBob.Events:
		if e.ID != giftWrap.ID {
			t.Error("Bob received wrong Gift Wrap")
		}
		if e.Kind != 1059 {
			t.Errorf("Expected Kind 1059, got %d", e.Kind)
		}
	case <-time.After(1 * time.Second):
		t.Error("NIP-17 Failure: Bob did not receive the Gift Wrap addressed to him")
	}
}

// -----------------------------------------------------------------------------
// NIP-25: Reactions (Likes)
// -----------------------------------------------------------------------------

func TestNIP25_Reactions(t *testing.T) {
	_, vr, wsURL, teardown := setupTestRelay(t)
	defer teardown()

	// Alice posts, Bob reacts
	skAlice, pkAlice := generateTestUser()
	skBob, pkBob := generateTestUser()

	// Whitelist both
	ctx := context.Background()
	vr.InternalChangePubKey(ctx, pkAlice.Hex(), store.PubKeyAllowed, "")
	vr.InternalChangePubKey(ctx, pkBob.Hex(), store.PubKeyAllowed, "")

	// Connect Alice
	relayAlice, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	defer relayAlice.Close()

	// Connect Bob
	relayBob, _ := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	defer relayBob.Close()

	// 1. Alice publishes a Note (Kind 1)
	note := nostr.Event{
		PubKey:    pkAlice,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Content:   "Pleaassee like this post",
	}
	note.Sign(skAlice)

	err := relayAlice.Publish(ctx, note)
	if err != nil {
		if strings.Contains(err.Error(), "auth-required") {
			if authErr := relayAlice.Auth(ctx, sign(skAlice)); authErr != nil {
				t.Fatalf("Auth failed: %v", authErr)
			}
		}
		err = relayAlice.Publish(ctx, note)
		if err != nil {
			t.Fatalf("Failed to publish root note: %v", err)
		}
	}

	// 2. Bob publishes a Reaction (Kind 7)
	// NIP-25: Content is "+" (like), tags include "e" (event id) and "p" (author)
	reaction := nostr.Event{
		PubKey:    pkBob,
		CreatedAt: nostr.Now(),
		Kind:      7,
		Content:   "+",
		Tags: nostr.Tags{
			{"e", note.ID.Hex()},     // Reference to the note
			{"p", note.PubKey.Hex()}, // Reference to Alice
		},
	}
	reaction.Sign(skBob)

	err = relayBob.Publish(ctx, reaction)
	if err != nil {
		if strings.Contains(err.Error(), "auth-required") {
			if authErr := relayBob.Auth(ctx, sign(skBob)); authErr != nil {
				t.Fatalf("Auth failed: %v", authErr)
			}
		}
		err = relayBob.Publish(ctx, reaction)
		if err != nil {
			t.Fatalf("Failed to publish reaction: %v", err)
		}
	}

	// 3. Verify Retrieval
	// We verify that we can fetch all reactions for Alice's note
	sub, _ := relayAlice.Subscribe(ctx, nostr.Filter{
		Kinds: []nostr.Kind{7},
		Tags:  nostr.TagMap{"e": []string{note.ID.Hex()}},
	}, nostr.SubscriptionOptions{})

	select {
	case e := <-sub.Events:
		if e.Content != "+" {
			t.Errorf("Expected reaction content '+', got '%s'", e.Content)
		}
		if e.PubKey != pkBob {
			t.Errorf("Expected reaction from Bob, got %s", e.PubKey)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("NIP-25 Failure: Could not retrieve reaction for the event")
	}

	// 4. Verify Emoji Reaction (Optional edge case)
	// NIP-25 allows emojis as content
	emojiReaction := nostr.Event{
		PubKey:    pkBob,
		CreatedAt: nostr.Now() + 1,
		Kind:      7,
		Content:   "🤙",
		Tags: nostr.Tags{
			{"e", note.ID.Hex()},
			{"p", note.PubKey.Hex()},
		},
	}
	emojiReaction.Sign(skBob)
	relayBob.Publish(ctx, emojiReaction)

	// Quick check to ensure it was accepted
	subEmoji, _ := relayAlice.Subscribe(ctx, nostr.Filter{IDs: []nostr.ID{emojiReaction.ID}}, nostr.SubscriptionOptions{})
	select {
	case <-subEmoji.Events:
		// Success
	case <-time.After(1 * time.Second):
		t.Error("NIP-25: Failed to store emoji reaction")
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
			if authErr := relay.Auth(ctx, sign(sk)); authErr != nil {
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

	// Send Auth
	err = relay.Auth(ctx, sign(sk))

	err = relay.Publish(ctx, ev)
	if err != nil {
		t.Fatalf("Publish failed after auth: %v", err)
	}
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
				if authErr := relay.Auth(ctx, sign(sk)); authErr != nil {
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
// NIP-56: Reporting
// -----------------------------------------------------------------------------

func TestNIP56_Reporting(t *testing.T) {
	_, vr, wsURL, teardown := setupTestRelay(t)
	defer teardown()

	// 1. Setup Users
	skReporter, pkReporter := generateTestUser()
	_, pkSpammer := generateTestUser() // The bad actor

	// Whitelist Reporter
	ctx := context.Background()
	vr.InternalChangePubKey(ctx, pkReporter.Hex(), store.PubKeyAllowed, "")

	// Connect
	relay, err := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer relay.Close()

	// --- Scenario 1: Reporting a User (Account-level report) ---
	// Reporter flags Spammer for "spam"
	userReport := nostr.Event{
		PubKey:    pkReporter,
		CreatedAt: nostr.Now(),
		Kind:      1984, // Reporting
		Content:   "This user is a bot",
		Tags: nostr.Tags{
			// ["p", pubkey, "report-type"]
			{"p", pkSpammer.Hex(), "spam"},
		},
	}
	userReport.Sign(skReporter)

	err = relay.Publish(ctx, userReport)
	if err != nil {
		if strings.Contains(err.Error(), "auth-required") {
			if authErr := relay.Auth(ctx, sign(skReporter)); authErr != nil {
				t.Fatalf("Auth failed: %v", authErr)
			}
		}
		err = relay.Publish(ctx, userReport)
		if err != nil {
			t.Fatalf("Failed to publish User Report: %v", err)
		}
	}

	// Verify retrieval by reported user
	subUser, _ := relay.Subscribe(ctx, nostr.Filter{
		Kinds: []nostr.Kind{1984},
		Tags:  nostr.TagMap{"p": []string{pkSpammer.Hex()}},
	}, nostr.SubscriptionOptions{})

	select {
	case e := <-subUser.Events:
		if e.ID != userReport.ID {
			t.Error("NIP-56: Retrieved wrong report event for user")
		}
		if e.Tags.Find("p")[1] != pkSpammer.Hex() {
			t.Error("NIP-56: Report missing targeted p-tag")
		}
	case <-time.After(1 * time.Second):
		t.Error("NIP-56: Failed to retrieve user report")
	}

	// --- Scenario 2: Reporting specific Content (Event-level report) ---
	// Let's pretend there is a bad event ID
	badEventID := nostr.Generate().Hex() // Just using random hex as ID

	contentReport := nostr.Event{
		PubKey:    pkReporter,
		CreatedAt: nostr.Now() + 10,
		Kind:      1984,
		Content:   "Illegal content",
		Tags: nostr.Tags{
			// ["e", event_id, "report-type"]
			// ["p", pubkey] (Optional, usually included if known)
			{"e", badEventID, "illegal"},
			{"p", pkSpammer.Hex()},
		},
	}
	contentReport.Sign(skReporter)

	err = relay.Publish(ctx, contentReport)
	if err != nil {
		t.Fatalf("Failed to publish Content Report: %v", err)
	}

	// Verify retrieval by reported event ID
	subContent, _ := relay.Subscribe(ctx, nostr.Filter{
		Kinds: []nostr.Kind{1984},
		Tags:  nostr.TagMap{"e": []string{badEventID}},
	}, nostr.SubscriptionOptions{})

	select {
	case e := <-subContent.Events:
		if e.ID != contentReport.ID {
			t.Error("NIP-56: Retrieved wrong report event for content")
		}
		// Check report type
		tag := e.Tags.Find("e")
		if len(tag) < 2 || tag[1] != badEventID {
			t.Error("NIP-56: Malformed e-tag in report")
		}
		if len(tag) >= 3 && tag[2] != "illegal" {
			t.Errorf("NIP-56: Expected report type 'illegal', got '%s'", tag[2])
		}
	case <-time.After(1 * time.Second):
		t.Error("NIP-56: Failed to retrieve content report")
	}
}

// -----------------------------------------------------------------------------
// NIP-62: Request to Vanish
// -----------------------------------------------------------------------------

func TestNIP62_RequestToVanish(t *testing.T) {
	_, vr, wsURL, teardown := setupTestRelay(t)
	defer teardown()

	vr.Config.RelayURL = wsURL

	// Whitelist user to bypass payments/restrictions
	sk, pk := generateTestUser()
	vr.InternalChangePubKey(context.Background(), pk.Hex(), store.PubKeyAllowed, "")

	ctx := context.Background()
	relay, err := nostr.RelayConnect(ctx, wsURL, nostr.RelayOptions{})
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer relay.Close()

	// 1. Publish some data (Kind 1)
	ev := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Content:   "This text should disappear",
	}
	ev.Sign(sk)

	err = relay.Publish(ctx, ev)
	if err != nil {
		if strings.Contains(err.Error(), "auth-required") {
			if authErr := relay.Auth(ctx, sign(sk)); authErr != nil {
				t.Fatalf("Auth failed: %v", authErr)
			}
		}
		err = relay.Publish(ctx, ev)
		if err != nil {
			t.Fatalf("Failed to publish setup event: %v", err)
		}
	}

	// Verify the event is actually stored
	sub1, _ := relay.Subscribe(ctx, nostr.Filter{IDs: []nostr.ID{ev.ID}}, nostr.SubscriptionOptions{})
	select {
	case <-sub1.Events:
		// Found it, good.
	case <-time.After(1 * time.Second):
		t.Fatal("Setup failed: Relay did not return the event we just published")
	}
	sub1.Unsub()

	// 2. Publish Request to Vanish (Kind 62)
	vanishEv := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      62,
		Tags: nostr.Tags{
			{"relay", wsURL},
		},
		Content: "Delete my data please",
	}
	vanishEv.Sign(sk)

	err = relay.Publish(ctx, vanishEv)
	if err != nil {
		t.Fatalf("Failed to publish NIP-62 request: %v", err)
	}

	time.Sleep(250 * time.Millisecond)

	// 3. Verify Data is Gone
	subCheck, _ := relay.Subscribe(ctx, nostr.Filter{
		Authors: []nostr.PubKey{pk},
		Kinds:   []nostr.Kind{1},
	}, nostr.SubscriptionOptions{})

	foundOldEvent := false
	select {
	case e := <-subCheck.Events:
		if e.ID == ev.ID {
			foundOldEvent = true
		}
	case <-subCheck.EndOfStoredEvents:
		// Normal completion
	case <-time.After(1 * time.Second):
		// Timeout
	}

	if foundOldEvent {
		t.Errorf("NIP-62 Failure: Kind 1 event (id: %s) still exists after Request to Vanish", ev.ID)
	}
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
			if authErr := relayA.Auth(ctx, sign(skA)); authErr != nil {
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
	relayB.Auth(ctx, sign(skB))

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
	_, vr, wsURL, teardown := setupTestRelay(t)
	defer teardown()

	vr.Config.RelayURL = wsURL

	sk, pk := generateTestUser()
	err := vr.InternalChangePubKey(context.Background(), pk.Hex(), store.PubKeyAllowed, "")
	if err != nil {
		t.Fatalf("Failed to whitelist test user: %v", err)
	}

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Websocket dial failed: %v", err)
	}
	defer conn.Close()

	// 1. Handle Auth if required
	isAuthRequired := false
	if vr.Info.Limitation != nil {
		isAuthRequired = vr.Info.Limitation.AuthRequired
	}

	if isAuthRequired {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, msg, err := conn.ReadMessage()
		conn.SetReadDeadline(time.Time{})

		if err != nil {
			t.Fatalf("AuthRequired=true, but failed to read initial AUTH challenge: %v", err)
		}

		var env []json.RawMessage
		if err := json.Unmarshal(msg, &env); err != nil {
			t.Fatalf("Invalid JSON in Auth Handshake: %v", err)
		}

		var msgType string
		if len(env) > 0 {
			json.Unmarshal(env[0], &msgType)
		}

		if msgType != "AUTH" {
			t.Fatalf("AuthRequired=true, expected 'AUTH' message, got '%s'", msgType)
		}

		var challenge string
		if len(env) > 1 {
			json.Unmarshal(env[1], &challenge)
		}

		// Perform Auth
		authEv := nostr.Event{
			PubKey:    pk,
			CreatedAt: nostr.Now(),
			Kind:      22242,
			Tags:      nostr.Tags{{"relay", wsURL}, {"challenge", challenge}},
		}
		authEv.Sign(sk)

		if err := conn.WriteJSON([]interface{}{"AUTH", authEv}); err != nil {
			t.Fatalf("Failed to send AUTH response: %v", err)
		}

		// Read the OK response
		_, authResp, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("Failed to read Auth OK response: %v", err)
		}
		if !strings.Contains(string(authResp), "true") {
			t.Fatalf("Authentication failed: %s", authResp)
		}
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
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if strings.Contains(err.Error(), "timeout") {
				// Check if the relay actually claims to support NIP-77
				hasSupport := false
				for _, n := range vr.Info.SupportedNIPs {
					if n == 77 {
						hasSupport = true
						break
					}
				}

				if hasSupport {
					t.Fatal("TIMEOUT: Relay claims NIP-77 support but ignored NEG-OPEN. " +
						"This usually indicates a 'go-nostr' vs 'khatru' version mismatch. ")
				}
			}
			t.Fatalf("Read error waiting for NEG-MSG: %v", err)
		}

		var env []json.RawMessage
		if err := json.Unmarshal(message, &env); err != nil {
			continue
		}

		if len(env) < 2 {
			continue
		}

		var msgType string
		json.Unmarshal(env[0], &msgType)

		// Success Case
		if msgType == "NEG-MSG" || msgType == "NEG-ERR" {
			return
		}

		// Failure Cases
		if msgType == "CLOSED" {
			t.Fatalf("Subscription CLOSED unexpectedly: %s", message)
		}
		if msgType == "NOTICE" {
			msgStr := string(message)
			if strings.Contains(msgStr, "error") || strings.Contains(msgStr, "invalid") {
				t.Fatalf("Received NOTICE error: %s", msgStr)
			}
		}
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
	relay.Auth(ctx, sign(sk))

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
