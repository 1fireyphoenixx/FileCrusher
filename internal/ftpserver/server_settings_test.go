package ftpserver

import "testing"

func TestGetSettingsHonorsDisableActiveMode(t *testing.T) {
	d := &mainDriver{disableActiveMode: true}
	s, err := d.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if !s.DisableActiveMode {
		t.Fatalf("expected DisableActiveMode true")
	}

	d.disableActiveMode = false
	s, err = d.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings (enabled): %v", err)
	}
	if s.DisableActiveMode {
		t.Fatalf("expected DisableActiveMode false")
	}
}
