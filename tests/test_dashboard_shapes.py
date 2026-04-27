def test_risk_dollars_shape_contract():
    sample = {
        "by_severity": {
            "Critical": {"count": 1, "dollars": 50000},
            "High": {"count": 2, "dollars": 20000},
            "Medium": {"count": 0, "dollars": 0},
            "Low": {"count": 3, "dollars": 300},
        }
    }
    sample["total_dollars"] = sum(item["dollars"] for item in sample["by_severity"].values())
    assert sample["total_dollars"] == 70300
