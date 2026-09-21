import json

from telemetry_scrubber.__main__ import main


def test_cli_scrubs_jsonl(tmp_path, capsys):
    f = tmp_path / "dump.jsonl"
    f.write_text(json.dumps({"body": "user a@b.com", "attributes": {"http.route": "/x"}}) + "\n\n")
    assert main([str(f)]) == 0
    out, err = capsys.readouterr()
    assert json.loads(out) == {"body": "user [REDACTED:email]", "attributes": {"http.route": "/x"}}
    assert "lines=1" in err and "email" in err
