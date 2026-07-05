from siem_hunter.parser import parse_syslog_line, parse_lines


def test_syslog_extracts_failed_password_fields():
    line = ("Mar 10 13:58:01 web01 sshd[2107]: Failed password for root "
            "from 45.83.19.7 port 55234 ssh2")
    ev = parse_syslog_line(line, "auth.log", assume_year=2026)
    assert ev is not None
    assert ev.get("program") == "sshd"
    assert ev.get("user") == "root"
    assert ev.get("src_ip") == "45.83.19.7"
    assert ev.get("pid") == 2107
    assert ev.timestamp.year == 2026


def test_syslog_extracts_invalid_user():
    line = "Mar 10 13:58:09 web01 sshd[2115]: Invalid user oracle from 45.83.19.7 port 55271"
    ev = parse_syslog_line(line, "auth.log", assume_year=2026)
    assert ev.get("user") == "oracle"
    assert ev.get("src_ip") == "45.83.19.7"


def test_unparseable_line_is_skipped():
    events = list(parse_lines(["totally not a syslog line", ""], "x", fmt="syslog"))
    assert events == []


def test_json_format_parsing():
    line = '{"timestamp": "2026-03-10T10:00:00Z", "program": "sshd", "src_ip": "1.2.3.4"}'
    (ev,) = list(parse_lines([line], "events.json", fmt="json"))
    assert ev.get("program") == "sshd"
    assert ev.get("src_ip") == "1.2.3.4"
