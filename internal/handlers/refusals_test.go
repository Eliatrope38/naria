package handlers

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// An anonymous visitor triggers refusals at will: the owner hears of them once a
// day, sooner only after a failed send, and the count shown on the form page
// clears without reopening the alert window.
func TestRefusalWatch(t *testing.T) {
	var w refusalWatch
	id := uuid.New()
	now := time.Now()

	if !w.record(id, now) {
		t.Fatal("première alerte non due")
	}
	if w.record(id, now.Add(time.Hour)) {
		t.Fatal("seconde alerte dans la journée")
	}
	if !w.record(id, now.Add(refusalAlertEvery)) {
		t.Fatal("alerte non due après un jour")
	}
	if n := w.count(id); n != 3 {
		t.Fatalf("compte = %d, 3 attendu", n)
	}

	w.retrySoon(id)
	if w.record(id, time.Now()) {
		t.Fatal("nouvel essai avant refusalAlertRetry")
	}
	if !w.record(id, time.Now().Add(refusalAlertRetry+time.Second)) {
		t.Fatal("nouvel essai non dû après refusalAlertRetry")
	}

	w.reset(id)
	if n := w.count(id); n != 0 {
		t.Fatalf("compte après remise à zéro = %d", n)
	}
	if w.record(id, time.Now().Add(refusalAlertRetry+2*time.Second)) {
		t.Fatal("la remise à zéro rouvre l'alerte")
	}
	if n := w.count(uuid.New()); n != 0 {
		t.Fatalf("formulaire inconnu : compte = %d", n)
	}
}
