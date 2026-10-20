import urllib.error

from siem_hunter.elastic import ElasticClient


def test_connect_fails_when_index_setup_fails(monkeypatch):
    client = ElasticClient()

    def request(method, path, body=None):
        if method == "PUT":
            raise urllib.error.URLError("index setup unavailable")
        return {}

    monkeypatch.setattr(client, "_request", request)

    assert client.connect() is False
    assert client.enabled is False
