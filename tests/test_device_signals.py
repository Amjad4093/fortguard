"""The extra sensors and device facts (magnetometer, proximity, battery, network, ...).

These are accepted in the same signed batches as the original signals, stored, and counted. Anything
unknown is refused, and typed text can still never enter any field.
"""

import copy


def _batch(enrolled, resign):
    session = enrolled()
    return session, copy.deepcopy(session["batches"][0])


def _sample(ts, x=0.1, y=0.2, z=9.8):
    return {"x": x, "y": y, "z": z, "ts": ts}


def test_extra_sensors_and_device_facts_are_accepted(api, enrolled, resign, clock):
    session, batch = _batch(enrolled, resign)
    ts = batch["timestamp_ms"]
    batch["sensor_data"]["magnetometer"] = [_sample(ts + i) for i in range(5)]
    batch["sensor_data"]["proximity"] = [_sample(ts + 10, x=0.0, y=0.0, z=0.0)]
    batch["environment"].update({
        "battery_level": 72, "charging": False, "network_type": "wifi", "locale": "en-PK",
        "timezone": "Asia/Karachi", "screen_width": 1080, "screen_height": 2400, "density": 2.75,
        "app_install_age_days": 12, "free_storage_mb": 4096,
    })
    status, body = api.post("/v1/telemetry/stream", resign(batch, session))
    assert status == 202, body
    expected_sensor = (len(session["batches"][0]["sensor_data"]["accelerometer"])
                       + len(session["batches"][0]["sensor_data"]["gyroscope"]) + 6)
    assert body["accepted"]["sensor"] == expected_sensor


def test_unknown_sensor_is_refused(api, enrolled, resign):
    session, batch = _batch(enrolled, resign)
    batch["sensor_data"]["heart_rate"] = [_sample(batch["timestamp_ms"])]
    status, body = api.post("/v1/telemetry/stream", resign(batch, session))
    assert status == 400


def test_out_of_range_battery_is_refused(api, enrolled, resign):
    session, batch = _batch(enrolled, resign)
    batch["environment"]["battery_level"] = 150
    status, _ = api.post("/v1/telemetry/stream", resign(batch, session))
    assert status == 400


def test_unknown_network_type_is_refused(api, enrolled, resign):
    session, batch = _batch(enrolled, resign)
    batch["environment"]["network_type"] = "satellite"
    status, _ = api.post("/v1/telemetry/stream", resign(batch, session))
    assert status == 400


def test_free_text_cannot_be_smuggled_in_as_a_device_fact(api, enrolled, resign):
    session, batch = _batch(enrolled, resign)
    batch["environment"]["locale"] = "hello world, my password is 1234"
    status, _ = api.post("/v1/telemetry/stream", resign(batch, session))
    assert status == 400


def test_unknown_environment_field_is_refused(api, enrolled, resign):
    session, batch = _batch(enrolled, resign)
    batch["environment"]["contacts_count"] = 42
    status, _ = api.post("/v1/telemetry/stream", resign(batch, session))
    assert status == 400
