from siem_hunter.pipeline import Pipeline


def test_reusing_pipeline_does_not_leak_correlation_state(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "threshold.yml").write_text(
        "id: TEST-THRESHOLD\ntitle: test\nlevel: high\ntype: threshold\n"
        "detection:\n  selection:\n    message|contains: failed\n"
        "  condition: selection\ngroup_by: src_ip\n"
        "threshold:\n  count: 3\n  window_seconds: 60\n"
    )
    first = tmp_path / "first.jsonl"
    first.write_text(
        '{"timestamp":"2026-01-01T00:00:00Z","message":"failed","src_ip":"1.2.3.4"}\n'
        '{"timestamp":"2026-01-01T00:00:01Z","message":"failed","src_ip":"1.2.3.4"}\n'
    )
    second = tmp_path / "second.jsonl"
    second.write_text(
        '{"timestamp":"2026-01-01T00:00:02Z","message":"failed","src_ip":"1.2.3.4"}\n'
    )

    pipeline = Pipeline(rules)
    assert pipeline.run(first, fmt="json") == []
    assert pipeline.run(second, fmt="json") == []
