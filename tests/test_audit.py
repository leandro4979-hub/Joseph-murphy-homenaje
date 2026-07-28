from carina.audit.append_only import AppendOnlyAuditLog


def test_audit_redacts_sensitive_values_and_returns_copies():
    audit = AppendOnlyAuditLog()
    audit.append("test", {"intent_id": "int_01"}, {"token": "secret", "nested": {"password": "bad"}})
    entry = audit.entries()[0]
    assert entry["details"] == {"token": "[REDACTED]", "nested": {"password": "[REDACTED]"}}
    entry["event"] = "tampered"
    assert audit.entries()[0]["event"] == "test"
