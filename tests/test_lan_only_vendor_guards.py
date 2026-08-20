import network_diagnostics as nd


def test_lan_guard_refuses_explicit_wifi(monkeypatch):
    monkeypatch.setattr(nd, '_list_iface_names', lambda include_virtual=False: ['wlan0', 'eth0'])
    monkeypatch.setattr(nd, '_is_wireless', lambda iface: iface == 'wlan0')

    iface, err = nd._lan_guard_iface('wlan0', 'Cisco Guard')

    assert iface is None
    assert err['success'] is False
    assert 'refusing Wi-Fi interface wlan0' in err['error']


def test_lan_guard_auto_does_not_fall_back_to_wifi(monkeypatch):
    monkeypatch.setattr(nd, '_list_iface_names', lambda include_virtual=False: ['wlan0'])
    monkeypatch.setattr(nd, '_is_wireless', lambda iface: iface == 'wlan0')
    monkeypatch.setattr(nd, '_default_route_iface', lambda: 'wlan0')

    iface, err = nd._lan_guard_iface(None, 'Juniper Guard')

    assert iface is None
    assert err['success'] is False
    assert 'no wired capture interface is up' in err['error']


def test_lan_guard_auto_prefers_wired_default(monkeypatch):
    monkeypatch.setattr(nd, '_list_iface_names', lambda include_virtual=False: ['wlan0', 'eth0', 'eth1'])
    monkeypatch.setattr(nd, '_is_wireless', lambda iface: iface == 'wlan0')
    monkeypatch.setattr(nd, '_default_route_iface', lambda: 'eth1')

    def fake_open(path, *args, **kwargs):
        class FakeFile:
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc, tb):
                return False
            def read(self):
                return '1'
        return FakeFile()

    monkeypatch.setattr('builtins.open', fake_open)

    iface, err = nd._lan_guard_iface(None, 'Arista Guard')

    assert err is None
    assert iface == 'eth1'
