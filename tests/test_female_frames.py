"""Female (shieldmaiden) on-device character frames.

A mesh unit named after a woman (or pinned mesh_viking_gender=female) must draw
the status/woman frames on every screen that shows the viking: the screens fed
by update_image_randomizer (imagegen) and the round GC9A01, which walks the
frame pools itself through active_image_series().
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault('RAGNAR_HEADLESS', '1')

Image = pytest.importorskip('PIL.Image')
shared = pytest.importorskip('shared')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATUS_DIR = os.path.join(REPO, 'resources', 'images', 'status')


def _unit(**cfg):
    """A SharedData with only what the frame code touches (no hardware init)."""
    sd = shared.SharedData.__new__(shared.SharedData)
    sd.config = dict(cfg)
    sd.statuspicdir = STATUS_DIR
    sd.status_list = ['IDLE', 'NetworkScanner', 'SSHBruteforce']
    sd.width, sd.height = 122, 250
    sd.female_image_series = {}
    sd._female_unit_cache = None
    sd.imagegen = None
    sd.ragnarstatustext = 'IDLE'
    male = Image.open(os.path.join(STATUS_DIR, 'IDLE', 'IDLE1.bmp'))
    sd.IDLE = male
    sd.image_series = {s: [male] for s in sd.status_list}
    sd.load_female_images(1.0)
    return sd


def test_female_frames_load_as_1bit_at_frame_height():
    sd = _unit()
    assert set(sd.female_image_series) >= set(sd.status_list)
    pool = sd.female_image_series['IDLE']
    assert len(pool) >= 8
    for frame in pool:
        assert frame.mode == '1'
        assert frame.height == 78
        assert frame.width <= 78
        # Line art: mostly white with some ink, never blank or a solid blob.
        ink = frame.histogram()[0] / (frame.width * frame.height)
        assert 0.02 < ink < 0.5


@pytest.mark.parametrize('cfg,expected', [
    ({'mesh_enabled': True, 'mesh_viking_gender': 'female', 'mesh_viking_name': 'Xena'}, True),
    ({'mesh_enabled': True, 'mesh_viking_gender': 'male', 'mesh_viking_name': 'Lagertha'}, False),
    ({'mesh_enabled': True, 'mesh_viking_gender': '', 'mesh_viking_name': 'Lagertha Ironside'}, True),
    ({'mesh_enabled': True, 'mesh_viking_gender': '', 'mesh_viking_name': 'Bjorn Ironside'}, False),
    # An explicit pin holds off the mesh; a name alone does not.
    ({'mesh_enabled': False, 'mesh_viking_gender': 'female', 'mesh_viking_name': ''}, True),
    ({'mesh_enabled': False, 'mesh_viking_gender': '', 'mesh_viking_name': 'Lagertha Ironside'}, False),
    ({'mesh_enabled': False, 'mesh_viking_gender': None, 'mesh_viking_name': ''}, False),
])
def test_gender_resolution_matches_web_portrait(cfg, expected):
    assert _unit(**cfg)._unit_is_female() is expected


def test_female_unit_animates_female_frames_for_every_status():
    sd = _unit(mesh_enabled=True, mesh_viking_gender='female')
    female = {id(f) for f in sd.female_image_series['IDLE']}
    for status in sd.status_list + ['SomethingNew']:
        sd.ragnarstatustext = status
        sd.update_image_randomizer()
        assert id(sd.imagegen) in female
        assert sd.x_center == (sd.width - sd.imagegen.width) // 2
        assert sd.y_bottom == sd.height - sd.imagegen.height
    assert sd.active_image_series() is sd.female_image_series


def test_male_unit_keeps_default_frames():
    sd = _unit(mesh_enabled=True, mesh_viking_gender='male')
    sd.update_image_randomizer()
    assert sd.imagegen is sd.image_series['IDLE'][0]
    assert sd.active_image_series() is sd.image_series


def test_gender_change_at_runtime_switches_frames():
    sd = _unit(mesh_enabled=True, mesh_viking_gender='male')
    assert sd.active_image_series() is sd.image_series
    sd.config['mesh_viking_gender'] = 'female'
    assert sd.active_image_series() is sd.female_image_series
    sd.config['mesh_viking_gender'] = ''
    sd.config['mesh_viking_name'] = 'Lagertha Ironside'
    assert sd.active_image_series() is sd.female_image_series
    sd.config['mesh_enabled'] = False
    assert sd.active_image_series() is sd.image_series


def test_missing_female_art_falls_back_to_default_frames():
    sd = _unit(mesh_enabled=True, mesh_viking_gender='female')
    sd.female_image_series = {}
    sd.update_image_randomizer()
    assert sd.imagegen is sd.image_series['IDLE'][0]
    assert sd.active_image_series() is sd.image_series
