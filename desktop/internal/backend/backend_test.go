package backend

import "testing"

func TestParseReadyURL(t *testing.T) {
	got, ok := ParseReadyURL("DeltaScope · Omega security research workbench: http://127.0.0.1:49321/")
	if !ok || got.String() != "http://127.0.0.1:49321/" {
		t.Fatalf("got %v ok=%v", got, ok)
	}
	if _, ok := ParseReadyURL("Evidence source: x"); ok {
		t.Fatal("unexpected match")
	}
}
