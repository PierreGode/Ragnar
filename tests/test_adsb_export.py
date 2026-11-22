"""ADS-B per-UTC-day unique-aircraft log + SBS export (adsb.py).

Ragnar's live tracker only keeps what is overhead now; for Wardrift's Aircraft
Watch (each ICAO counts once per UTC day) the tracker also logs every new ICAO
to a per-day file. These tests cover: dedup of repeats, field back-fill across
rows, the SBS export (header, 22 columns, message-type by fields present) and
that Ragnar's own parse_sbs reads the export back.
"""

import time

import pytest

import adsb


@pytest.fixture
def day_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(adsb, "_DATA_DIR", str(tmp_path))
    return tmp_path


def _ingest(*recs):
    tr = adsb.AdsbTracker()
    for r in recs:
        tr._ingest(dict(r))
    return adsb._utc_today()


def test_unique_per_day_dedups_repeats(day_dir):
    day = _ingest(
        {"icao": "ABC123", "callsign": "SAS1", "alt": 35000},
        {"icao": "ABC123", "alt": 35020},          # same ICAO again -> not counted twice
        {"icao": "DEF456", "lat": 59.3, "lon": 18.0},
    )
    assert adsb.day_icao_count(day) == 2
    assert sorted(o["icao"] for o in adsb.observations(day)) == ["ABC123", "DEF456"]


def test_fields_backfill_across_rows(day_dir):
    # First sighting has no callsign; a later row for the same ICAO does.
    day = _ingest(
        {"icao": "ABC123", "alt": 1000},
        {"icao": "ABC123", "callsign": "RYR9"},
    )
    o = adsb.observations(day)[0]
    assert o["callsign"] == "RYR9" and o["alt"] == 1000


def test_sbs_export_shape_and_message_types(day_dir):
    day = _ingest(
        {"icao": "AAA111", "lat": 59.3, "lon": 18.0, "alt": 12000},  # -> MSG,3
        {"icao": "BBB222", "callsign": "DLH1"},                       # -> MSG,1
        {"icao": "CCC333"},                                          # -> MSG,8
    )
    sbs = adsb.export_sbs(day)
    lines = sbs.splitlines()
    assert lines[0] == "# timezone=UTC"
    rows = lines[1:]
    assert all(len(r.split(",")) == 22 for r in rows)
    by_icao = {r.split(",")[4]: r.split(",")[1] for r in rows}
    assert by_icao == {"AAA111": "3", "BBB222": "1", "CCC333": "8"}
    # Ragnar's own SBS parser reads every exported row back.
    assert {adsb.parse_sbs(r)["icao"] for r in rows} == {"AAA111", "BBB222", "CCC333"}


def test_export_empty_day_is_blank(day_dir):
    assert adsb.export_sbs("20200101") == ""
    assert adsb.day_icao_count("20200101") == 0


def test_mid_day_restart_reseeds_from_disk(day_dir):
    day = _ingest({"icao": "ABC123"}, {"icao": "DEF456"})
    # A fresh tracker (simulating a restart) must not re-log aircraft already
    # recorded today — it seeds its seen-set from the day file.
    tr2 = adsb.AdsbTracker()
    tr2._ingest({"icao": "ABC123"})          # already logged today
    tr2._ingest({"icao": "999FFF"})          # new
    assert adsb.day_icao_count(day) == 3
