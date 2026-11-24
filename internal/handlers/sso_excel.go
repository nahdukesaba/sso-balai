package handlers

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

type importedUserRow struct {
	Email    string
	FullName string
	Jabatan  string
	Phone    string
}

// buildUserImportTemplateXLSX generates a minimal, standards-compliant .xlsx workbook
// with columns: email, nama_lengkap, jabatan, no_hp (no password column; default is balaisumut).
func buildUserImportTemplateXLSX() ([]byte, error) {
	rows := [][]string{
		{"email", "nama_lengkap", "jabatan", "no_hp"},
		{"budi@bp3kpsumatera2.com", "Budi Santoso", "Kepala Seksi Perencanaan", "08123456789"},
		{"sari@bp3kpsumatera2.com", "Sari Dewi", "Analis Kebijakan Ahli Pertama", ""},
	}

	var sheetXML strings.Builder
	sheetXML.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	sheetXML.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	sheetXML.WriteString(`<cols>`)
	sheetXML.WriteString(`<col min="1" max="1" width="32" customWidth="1"/>`)
	sheetXML.WriteString(`<col min="2" max="2" width="28" customWidth="1"/>`)
	sheetXML.WriteString(`<col min="3" max="3" width="32" customWidth="1"/>`)
	sheetXML.WriteString(`<col min="4" max="4" width="18" customWidth="1"/>`)
	sheetXML.WriteString(`</cols>`)
	sheetXML.WriteString(`<sheetData>`)
	colLetters := []string{"A", "B", "C", "D"}
	for rIdx, row := range rows {
		rowNum := rIdx + 1
		sheetXML.WriteString(fmt.Sprintf(`<row r="%d">`, rowNum))
		for cIdx, val := range row {
			if cIdx >= len(colLetters) {
				break
			}
			ref := fmt.Sprintf("%s%d", colLetters[cIdx], rowNum)
			var escaped bytes.Buffer
			_ = xml.EscapeText(&escaped, []byte(val))
			styleAttr := ""
			if rowNum == 1 {
				styleAttr = ` s="1"`
			}
			sheetXML.WriteString(fmt.Sprintf(`<c r="%s" t="inlineStr"%s><is><t>%s</t></is></c>`, ref, styleAttr, escaped.String()))
		}
		sheetXML.WriteString(`</row>`)
	}
	sheetXML.WriteString(`</sheetData></worksheet>`)

	files := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-officedocument.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
			`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
			`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>` +
			`</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
			`</Relationships>`,
		"xl/workbook.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
			`<sheets><sheet name="Template User SSO" sheetId="1" r:id="rId1"/></sheets>` +
			`</workbook>`,
		"xl/_rels/workbook.xml.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
			`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
			`</Relationships>`,
		"xl/styles.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
			`<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>` +
			`<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>` +
			`<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>` +
			`<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
			`<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>` +
			`</styleSheet>`,
		"xl/worksheets/sheet1.xml": sheetXML.String(),
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	order := []string{
		"[Content_Types].xml",
		"_rels/.rels",
		"xl/workbook.xml",
		"xl/_rels/workbook.xml.rels",
		"xl/styles.xml",
		"xl/worksheets/sheet1.xml",
	}
	for _, name := range order {
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := io.WriteString(w, files[name]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
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

type xlsxSharedStrings struct {
	Items []struct {
		T string `xml:"t"`
		R []struct {
			T string `xml:"t"`
		} `xml:"r"`
	} `xml:"si"`
}

type xlsxWorksheet struct {
	Rows []struct {
		Cells []struct {
			Ref string `xml:"r,attr"`
			T   string `xml:"t,attr"`
			V   string `xml:"v"`
			IS  struct {
				T string `xml:"t"`
				R []struct {
					T string `xml:"t"`
				} `xml:"r"`
			} `xml:"is"`
		} `xml:"c"`
	} `xml:"sheetData>row"`
}

func readXLSXRows(data []byte) ([][]string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("file Excel (.xlsx) tidak valid: %w", err)
	}

	var sharedStrings []string
	var sheetFile *zip.File
	for _, f := range zr.File {
		switch f.Name {
		case "xl/sharedStrings.xml":
			rc, openErr := f.Open()
			if openErr == nil {
				var ss xlsxSharedStrings
				if decErr := xml.NewDecoder(rc).Decode(&ss); decErr == nil {
					for _, item := range ss.Items {
						if len(item.R) > 0 {
							var sb strings.Builder
							for _, run := range item.R {
								sb.WriteString(run.T)
							}
							sharedStrings = append(sharedStrings, sb.String())
						} else {
							sharedStrings = append(sharedStrings, item.T)
						}
					}
				}
				_ = rc.Close()
			}
		case "xl/worksheets/sheet1.xml":
			sheetFile = f
		default:
			if sheetFile == nil && strings.HasPrefix(f.Name, "xl/worksheets/sheet") && strings.HasSuffix(f.Name, ".xml") {
				sheetFile = f
			}
		}
	}

	if sheetFile == nil {
		return nil, fmt.Errorf("sheet Excel tidak ditemukan di dalam file .xlsx")
	}

	rc, err := sheetFile.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	var ws xlsxWorksheet
	if err := xml.NewDecoder(rc).Decode(&ws); err != nil {
		return nil, fmt.Errorf("gagal membaca isi sheet Excel: %w", err)
	}

	var out [][]string
	for _, r := range ws.Rows {
		if len(r.Cells) == 0 {
			continue
		}
		var row []string
		for _, c := range r.Cells {
			colIdx := xlsxCellColIndex(c.Ref)
			if colIdx < 0 {
				colIdx = len(row)
			}
			for len(row) <= colIdx {
				row = append(row, "")
			}
			var val string
			switch c.T {
			case "s":
				idx := 0
				if _, scanErr := fmt.Sscanf(strings.TrimSpace(c.V), "%d", &idx); scanErr == nil && idx >= 0 && idx < len(sharedStrings) {
					val = sharedStrings[idx]
				}
			case "inlineStr":
				if len(c.IS.R) > 0 {
					var sb strings.Builder
					for _, run := range c.IS.R {
						sb.WriteString(run.T)
					}
					val = sb.String()
				} else {
					val = c.IS.T
				}
			default:
				val = c.V
			}
			row[colIdx] = strings.TrimSpace(val)
		}
		out = append(out, row)
	}
	return out, nil
}

func xlsxCellColIndex(ref string) int {
	ref = strings.ToUpper(strings.TrimSpace(ref))
	if ref == "" {
		return -1
	}
	col := 0
	found := false
	for i := 0; i < len(ref); i++ {
		ch := ref[i]
		if ch >= 'A' && ch <= 'Z' {
			col = col*26 + int(ch-'A'+1)
			found = true
		} else {
			break
		}
	}
	if !found {
		return -1
	}
	return col - 1
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
