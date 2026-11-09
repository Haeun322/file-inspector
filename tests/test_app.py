from fastapi.testclient import TestClient
import app as m

c = TestClient(m.app)

def test_health():
    r = c.get("/api/health"); assert r.status_code == 200 and r.json()["version"] == m.VERSION

def test_analyze_text():
    r = c.post("/api/analyze", files={"file": ("a.txt", b"hello world " * 10)})
    j = r.json(); assert r.status_code == 200 and j["type"].startswith("text") and j["entropy"] < 5

def test_analyze_elf():
    hdr = b"\x7fELF\x02\x01" + b"\x00" * 10 + b"\x02\x00\x3e\x00" + b"\x00" * 40
    j = c.post("/api/analyze", files={"file": ("b", hdr)}).json()
    assert j["type"] == "ELF executable" and j["elf"]["machine"] == "x86-64" and j["elf"]["class"] == 64
