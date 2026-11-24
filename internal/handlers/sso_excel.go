package handlers

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/xuri/excelize/v2"
)

type importedUserRow struct {
	Email    string
	FullName string
	Jabatan  string
	Phone    string
}

// buildUserImportTemplateXLSX generates a standards-compliant .xlsx workbook via excelize
// with columns: email, nama_lengkap, jabatan, no_hp (no password column; default is balaisumut).
func buildUserImportTemplateXLSX() ([]byte, error) {
	const sheetName = "Template User SSO"

	f := excelize.NewFile()
	defer func() { _ = f.Close() }()

	if err := f.SetSheetName("Sheet1", sheetName); err != nil {
		return nil, err
	}

	headers := []string{"email", "nama_lengkap", "jabatan", "no_hp"}
	for idx, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(idx+1, 1)
		if err := f.SetCellValue(sheetName, cell, h); err != nil {
			return nil, err
		}
	}

	headerStyle, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true},
	})
	if err == nil {
		_ = f.SetCellStyle(sheetName, "A1", "D1", headerStyle)
	}

	examples := [][]string{
		{"budi@bp3kpsumatera2.com", "Budi Santoso", "Kepala Seksi Perencanaan", "08123456789"},
		{"sari@bp3kpsumatera2.com", "Sari Dewi", "Analis Kebijakan Ahli Pertama", ""},
	}
	for rIdx, row := range examples {
		for cIdx, val := range row {
			cell, _ := excelize.CoordinatesToCellName(cIdx+1, rIdx+2)
			if err := f.SetCellStr(sheetName, cell, val); err != nil {
				return nil, err
			}
		}
	}

	_ = f.SetColWidth(sheetName, "A", "A", 32)
	_ = f.SetColWidth(sheetName, "B", "B", 28)
	_ = f.SetColWidth(sheetName, "C", "C", 32)
	_ = f.SetColWidth(sheetName, "D", "D", 18)

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseUserImportSpreadsheet(filename string, data []byte) ([]importedUserRow, error) {
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(filename)))
	var rawRows [][]string
	var err error
	if ext == ".xlsx" || (len(data) >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 3 && data[3] == 4) {
		rawRows, err = readXLSXRows(data)
	} else {
		rawRows, err = readCSVRows(string(data))
	}
	if err != nil {
		return nil, err
	}
	return mapImportedUserRows(rawRows), nil
}

func readCSVRows(rawText string) ([][]string, error) {
	rawText = strings.TrimPrefix(strings.TrimSpace(rawText), "\ufeff")
	if rawText == "" {
		return nil, nil
	}
	firstLine := strings.SplitN(rawText, "\n", 2)[0]
	comma := ','
	if strings.Contains(firstLine, ";") && !strings.Contains(firstLine, ",") {
		comma = ';'
	}
	reader := csv.NewReader(bytes.NewBufferString(rawText))
	reader.Comma = comma
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	return reader.ReadAll()
}

func readXLSXRows(data []byte) ([][]string, error) {
	f, err := excelize.OpenReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("file Excel (.xlsx) tidak valid: %w", err)
	}
	defer func() { _ = f.Close() }()

	sheetName := f.GetSheetName(0)
	if sheetName == "" {
		return nil, fmt.Errorf("sheet Excel tidak ditemukan di dalam file .xlsx")
	}
	rows, err := f.GetRows(sheetName)
	if err != nil {
		return nil, fmt.Errorf("gagal membaca isi sheet Excel: %w", err)
	}
	return rows, nil
}

func mapImportedUserRows(rawRows [][]string) []importedUserRow {
	if len(rawRows) == 0 {
		return nil
	}

	emailIdx, nameIdx, jabatanIdx, phoneIdx := 0, 1, 2, 3
	startRow := 0

	// Detect header row automatically and map columns by name if present.
	first := rawRows[0]
	isHeader := false
	for _, cell := range first {
		h := strings.ToLower(strings.TrimSpace(cell))
		if h == "email" || strings.Contains(h, "nama") || strings.Contains(h, "jabatan") {
			isHeader = true
			break
		}
	}
	if isHeader {
		startRow = 1
		emailIdx, nameIdx, jabatanIdx, phoneIdx = -1, -1, -1, -1
		for idx, cell := range first {
			h := strings.ToLower(strings.TrimSpace(cell))
			switch {
			case emailIdx == -1 && strings.Contains(h, "email"):
				emailIdx = idx
			case nameIdx == -1 && (strings.Contains(h, "nama") || h == "name" || h == "full_name"):
				nameIdx = idx
			case jabatanIdx == -1 && (strings.Contains(h, "jabatan") || strings.Contains(h, "posisi") || strings.Contains(h, "title")):
				jabatanIdx = idx
			case phoneIdx == -1 && (strings.Contains(h, "hp") || strings.Contains(h, "telp") || strings.Contains(h, "phone") || strings.Contains(h, "wa")):
				phoneIdx = idx
			}
		}
		if emailIdx == -1 {
			emailIdx = 0
		}
		if nameIdx == -1 {
			nameIdx = 1
		}
	}

	getCol := func(row []string, idx int) string {
		if idx < 0 || idx >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[idx])
	}

	var result []importedUserRow
	for i := startRow; i < len(rawRows); i++ {
		row := rawRows[i]
		email := strings.ToLower(getCol(row, emailIdx))
		fullName := getCol(row, nameIdx)
		jabatan := getCol(row, jabatanIdx)
		phone := getCol(row, phoneIdx)
		if email == "" && fullName == "" {
			continue
		}
		result = append(result, importedUserRow{
			Email:    email,
			FullName: fullName,
			Jabatan:  jabatan,
			Phone:    phone,
		})
	}
	return result
}
