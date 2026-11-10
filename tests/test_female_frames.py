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
    # The per-status icon (28px), as load_images sets it. Not a frame.
    sd.IDLE = Image.open(os.path.join(STATUS_DIR, 'IDLE', 'IDLE.bmp'))
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
        # Same footprint as the default frames, so no screen layout changes.
        assert frame.size == (78, 78)
        # A shaded portrait: plenty of ink, but never blank or a solid blob.
        ink = frame.histogram()[0] / (frame.width * frame.height)
        assert 0.15 < ink < 0.6


def test_shipped_frames_are_ready_made_and_match_the_generator():
    """woman/*.png are the generator's output for woman/src/*.png, so the art
    can be re-tuned from the committed portrait crops."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'gen_female_frames', os.path.join(REPO, 'scripts', 'gen_female_frames.py'))
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    woman = os.path.join(STATUS_DIR, 'woman')
    names = sorted(n for n in os.listdir(woman) if n.endswith('.png'))
    sources = sorted(n for n in os.listdir(os.path.join(woman, 'src')) if n.endswith('.png'))
    expected = {n: (n, None) for n in sources}
    for base, kinds in gen.IDLE_VARIANTS.items():
        for kind in kinds:
            expected[f'idle_{base}_{kind}.png'] = (base + '.png', kind)
    assert names == sorted(expected)
    for name in names:
        shipped = Image.open(os.path.join(woman, name))
        assert shipped.mode == '1' and shipped.size == (78, 78)
        src_name, kind = expected[name]
        src = Image.open(os.path.join(woman, 'src', src_name))
        if kind:
            built = gen.render_idle_frame(src, src_name[:-4], kind)
        else:
            built = gen.render_frame(src)
        # Not byte-exact: resampling rounds differently across Pillow versions.
        diff = sum(bin(a ^ b).count('1') for a, b in zip(shipped.tobytes(), built.tobytes()))
        assert diff < 0.03 * 78 * 78, f'{name}: {diff} pixels differ'


def test_scaled_frames_keep_the_dither_crisp():
    # Large displays scale with NEAREST: 2x must be an exact pixel doubling.
    sd = _unit()
    base = sd.female_image_series['IDLE'][0]
    big = sd.image_series['IDLE'][0].resize((156, 156))
    sd.image_series = {s: [big] for s in sd.status_list}
    sd.load_female_images(2.0)
    doubled = sd.female_image_series['IDLE'][0]
    assert doubled.size == (156, 156)
    assert doubled.tobytes() == base.resize((156, 156), Image.NEAREST).tobytes()


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


def test_female_frames_follow_scaled_default_frames():
    sd = _unit()
    big = sd.image_series['IDLE'][0].resize((117, 117))
    sd.image_series = {s: [big] for s in sd.status_list}
    sd.load_female_images(1.5)
    assert {f.height for f in sd.female_image_series['IDLE']} == {117}


def test_female_frames_sized_without_default_frames():
    sd = _unit()
    sd.image_series = {}
    sd.load_female_images(1.0)
    assert {f.height for f in sd.female_image_series['IDLE']} == {78}


def test_idle_draws_extra_expression_frames_other_statuses_do_not():
    sd = _unit(mesh_enabled=True, mesh_viking_gender='female')
    woman = os.path.join(STATUS_DIR, 'woman')
    files = [n for n in os.listdir(woman) if n.endswith('.png')]
    extras = [n for n in files if n.startswith('idle_')]
    assert len(extras) >= 10
    idle = sd.female_image_series['IDLE']
    busy = sd.female_image_series['SSHBruteforce']
    assert len(idle) == len(files)
    assert len(busy) == len(files) - len(extras)
    # The plain portraits are in both pools; the extras only in IDLE.
    assert {id(f) for f in busy} < {id(f) for f in idle}
    # A status the loader has never heard of falls back to the IDLE pool.
    sd.ragnarstatustext = 'SomethingNew'
    sd.update_image_randomizer()
    assert id(sd.imagegen) in {id(f) for f in idle}


def test_idle_variants_change_only_the_face():
    """An expression variant must differ from its base portrait, but only
    around the eyes: helmet, hair and shoulders stay pixel-identical."""
    woman = os.path.join(STATUS_DIR, 'woman')
    for name in sorted(os.listdir(woman)):
        if not name.startswith('idle_'):
            continue
        base = name.split('_')[1] + '.png'
        a = Image.open(os.path.join(woman, base))
        b = Image.open(os.path.join(woman, name))
        from PIL import ImageChops
        box = ImageChops.difference(a.convert('L'), b.convert('L')).getbbox()
        assert box is not None, f'{name} is identical to {base}'
        x0, y0, x1, y1 = box
        assert y0 >= 38 and y1 <= 64, f'{name}: changed rows {y0}-{y1}'
        assert x1 - x0 <= 60, name
