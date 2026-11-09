"""The browser test client must sign exactly what the server verifies (needs Node)."""

import json
import pathlib
import re
import shutil
import subprocess

import pytest

from fortguard.signing import canonical_bytes, load_public_key, verify_payload

WEB = pathlib.Path(__file__).resolve().parent.parent / "fortguard" / "web"
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")

SCRIPT = r"""
const F = require(process.argv[1]);
const subtle = require('crypto').webcrypto.subtle;
(async () => {
  const pair = await subtle.generateKey({name: 'ECDSA', namedCurve: 'P-256'}, false, ['sign', 'verify']);
  const spki = new Uint8Array(await subtle.exportKey('spki', pair.publicKey));
  const payloads = [];
  for (let i = 0; i < 40; i++) {
    const r = (n) => F.round3((Math.random() - 0.5) * n);
    payloads.push({
      session_id: 'sess_abcdefgh', device_guid: 'dev_abcdefgh1234', app_id: 'com.example.mobilebank',
      timestamp_ms: 1800000000000 + i, nonce: 'n_' + i + 'abcdefghij', seq: i, consent: {behavioral: true},
      environment: {os: 'Web', os_version: 'browser', vpn: i % 2 === 0},
      touch_events: [{event_type: 'DOWN', x: r(2000), y: r(2000), pressure: Math.abs(r(1)), size: Math.abs(r(40)), timestamp_ms: 1800000000000 + i}],
      key_events: [], ui_events: [],
      sensor_data: {accelerometer: [{x: r(20), y: 9.81 + r(0.2), z: r(0.0008), ts: 1800000000000}],
                    gyroscope: [{x: r(0.0004), y: 0, z: -0.0001, ts: 1800000000000}]}
    });
  }
  const signed = [];
  for (const p of payloads) signed.push(await F.sign(p, pair.privateKey, subtle));
  const samples = [0, -0, 0.001, 0.1, 1.5, 100, 1800000000000, 12345.678, -0.0004, 1e-7, 3];
  const odd = samples.map(v => ({text: F.canonical({v: F.round3(v), "é": "naïve \"q\" \\ \n"}), v: F.round3(v)}));
  console.log(JSON.stringify({public_key: F.b64url(spki), signed, odd}));
})();
"""


@pytest.fixture(scope="module")
def node_output():
    out = subprocess.run(["node", "-e", SCRIPT, str(WEB / "fgcore.js")], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_browser_signatures_verify_on_the_server_side(node_output):
    key = load_public_key(node_output["public_key"])
    assert len(node_output["signed"]) == 40
    assert all(verify_payload(p, key) for p in node_output["signed"])


def test_changing_a_signed_browser_payload_breaks_it(node_output):
    key = load_public_key(node_output["public_key"])
    p = json.loads(json.dumps(node_output["signed"][0]))
    p["environment"]["vpn"] = not p["environment"]["vpn"]
    assert not verify_payload(p, key)


def test_canonical_text_matches_python_for_awkward_values(node_output):
    for item in node_output["odd"]:
        python_text = canonical_bytes({"v": item["v"], "é": "naïve \"q\" \\ \n"}).decode()
        # Python keeps the same key order (sorted); compare after parsing the JS text the same way.
        assert json.dumps(json.loads(item["text"]), sort_keys=True, separators=(",", ":"), ensure_ascii=False) == python_text


# --- Privacy: the test client's own capture code must not read what people type -----------------------------


def capture_section():
    html = (WEB / "phone.html").read_text()
    start = html.index("// --- capture")
    end = html.index("// --- sending")
    return html[start:end]


@pytest.mark.parametrize("pattern", [r"\.key\b", r"\.keyCode\b", r"\.code\b", r"\.which\b", r"\.data\b",
                                     r"clipboardData", r"\.value\b", r"inputType", r"getData"])
def test_capture_handlers_never_read_typed_content(pattern):
    code = re.sub(r"//.*", "", capture_section())  # comments may name what is forbidden
    assert not re.search(pattern, code), pattern
