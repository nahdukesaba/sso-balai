package handlers

import "testing"

func TestUserImportTemplateXLSXRoundTrip(t *testing.T) {
	data, err := buildUserImportTemplateXLSX()
	if err != nil {
		t.Fatalf("buildUserImportTemplateXLSX failed: %v", err)
	}
	rows, err := parseUserImportSpreadsheet("template-import-user-sso.xlsx", data)
	if err != nil {
		t.Fatalf("parseUserImportSpreadsheet failed: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 example rows, got %d: %#v", len(rows), rows)
	}
	if rows[0].Email != "budi@bp3kpsumatera2.com" || rows[0].FullName != "Budi Santoso" ||
		rows[0].Jabatan != "Kepala Seksi Perencanaan" || rows[0].Phone != "08123456789" {
		t.Fatalf("unexpected row[0]: %#v", rows[0])
	}
	if rows[1].Email != "sari@bp3kpsumatera2.com" || rows[1].Jabatan != "Analis Kebijakan Ahli Pertama" || rows[1].Phone != "" {
		t.Fatalf("unexpected row[1]: %#v", rows[1])
	}
}
