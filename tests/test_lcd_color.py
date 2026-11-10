"""Colour on the 1.44" ST7735S LCD HAT: the full-colour character sprites and
the colour main screen. Every other panel must keep its 1-bit rendering."""
import glob
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('RAGNAR_HEADLESS', '1')

Image = pytest.importorskip('PIL.Image')
from PIL import ImageDraw, ImageFont  # noqa: E402

shared = pytest.importorskip('shared')
display = pytest.importorskip('display')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATUS = os.path.join(REPO, 'resources', 'images', 'status')
STATIC = os.path.join(REPO, 'resources', 'images', 'static')
FONTS = os.path.join(REPO, 'resources', 'fonts')


def _px(img):
    """All pixels of an image (getdata is deprecated in newer Pillow)."""
    return img.get_flattened_data() if hasattr(img, 'get_flattened_data') else list(img.getdata())


def _sd(gender='male'):
    sd = shared.SharedData.__new__(shared.SharedData)
    sd.config = {'mesh_enabled': True, 'mesh_viking_gender': gender}
    sd.statuspicdir = STATUS
    sd.status_list = ['IDLE', 'SSHBruteforce']
    sd.width, sd.height = 128, 128
    sd.female_image_series = {}
    sd._female_unit_cache = None
    sd._color_sprite_cache = {}
    sd.imagegen = None
    sd.image_series = {
        st: [Image.open(f) for f in sorted(glob.glob(os.path.join(STATUS, st, st + '[0-9]*.bmp')))]
        for st in sd.status_list}
    sd.load_female_images(1.0)
    sd.ragnarstatustext = sd.ragnarorch_status = 'IDLE'
    sd.ragnarstatustext2 = 'WiFi: home'
    sd.ragnarsays = "Bored... Let's hack something!"
    sd.wifi_connected, sd.wifi_signal_quality, sd.ap_mode_active = True, 80, False
    sd.update_ragnarstatus = lambda: None
    sd.font_arial9 = ImageFont.truetype(os.path.join(FONTS, 'Arial.ttf'), 9)
    sd.font_arialbold = ImageFont.truetype(os.path.join(FONTS, 'Arial.ttf'), 12)
    sd.font_viking = ImageFont.truetype(os.path.join(FONTS, 'Viking.TTF'), 13)
    for n in ('target', 'port', 'vuln', 'cred', 'zombie', 'data', 'money', 'attacks'):
        setattr(sd, n, Image.open(os.path.join(STATIC, n + '.bmp')))
        setattr(sd, {'zombie': 'zombiesnbr', 'money': 'coinnbr'}.get(n, n + 'nbr'), 7)
    sd.update_image_randomizer()
    return sd


def _display(sd, **cfg):
    d = display.Display.__new__(display.Display)
    d.shared_data = sd
    d.config = dict({'epd_type': 'st7735s'}, **cfg)
    d.get_wifi_ip_last_octet = lambda: '.42'
    d._unit_display_title = lambda: 'RAGNAR'
    d.scale_factor_x = d.scale_factor_y = d.render_sx = d.render_sy = 1.0
    d.render_w = d.render_h = 128
    d.button_listener = None
    return d


def _main_screen(d):
    """Render the compact main screen the way the display loop does."""
    if d._lcd_color_panel(128, 128):
        img = Image.new('RGB', (128, 128), display._WD_COLORS['bg'])
    else:
        img = Image.new('1', (128, 128), 255)
    d._render_main_compact(img, ImageDraw.Draw(img), 128, 128)
    return img


# ── colour sprites ──────────────────────────────────────────────────────────

def test_male_sprite_has_its_white_backdrop_cut_away():
    sd = _sd()
    frame = Image.open(os.path.join(STATUS, 'IDLE', 'IDLE1.bmp'))
    sprite = sd.color_sprite(frame)
    assert sprite.mode == 'RGBA' and sprite.size == frame.size
    alpha = sprite.split()[-1]
    for corner in ((0, 0), (77, 0), (0, 77), (77, 77)):
        assert alpha.getpixel(corner) == 0
    # The one-pixel floor line of the e-paper layout is not part of him.
    assert max(_px(alpha.crop((0, 77, 78, 78)))) == 0
    # The figure is opaque, including white enclosed by it (eye highlights).
    opaque = sum(1 for a in _px(alpha) if a == 255)
    assert opaque > 0.3 * 78 * 78
    # The face is as pale as the backdrop in places (within the cut-out
    # tolerance); it must survive because it is not connected to the border.
    whites = [(x, y) for y in range(32, 46) for x in range(24, 54)
              if sum(255 - c for c in frame.getpixel((x, y))) <= sd.COLOR_SPRITE_BG_TOLERANCE * 3]
    assert whites, 'expected near-white pixels inside the figure'
    assert all(alpha.getpixel(p) == 255 for p in whites)


def test_male_sprite_has_no_pale_halo():
    """Rim pixels blended with the white backdrop must not stay opaque, or the
    figure glows on the dark theme."""
    sd = _sd()
    sprite = sd.color_sprite(Image.open(os.path.join(STATUS, 'IDLE', 'IDLE1.bmp')))
    on_black = Image.new('RGB', sprite.size, (0, 0, 0))
    on_black.paste(sprite, (0, 0), sprite)
    alpha = sprite.split()[-1]
    rim = [(x, y) for y in range(1, 77) for x in range(1, 77)
           if alpha.getpixel((x, y)) and 0 in (alpha.getpixel((x - 1, y)), alpha.getpixel((x + 1, y)),
                                                alpha.getpixel((x, y - 1)), alpha.getpixel((x, y + 1)))]
    assert len(rim) > 50
    bright = [p for p in rim if min(on_black.getpixel(p)) > 200]
    assert len(bright) < 0.03 * len(rim)


def test_every_female_frame_has_a_colour_twin():
    sd = _sd('female')
    for frame in sd.female_image_series['IDLE']:
        sprite = sd.color_sprite(frame)
        assert sprite is not None and sprite.mode == 'RGBA'
        assert sprite.size == (156, 156)
        colours = sprite.convert('RGB').getcolors(maxcolors=100000)
        assert colours is None or len(colours) > 200       # real colour art
        assert sprite.getpixel((0, 0))[3] == 0              # transparent backdrop
    woman = os.path.join(STATUS, 'woman')
    assert sorted(n for n in os.listdir(woman) if n.endswith('.png')) == \
        sorted(os.listdir(os.path.join(woman, 'color')))


def test_colour_sprite_tracks_the_frame_not_a_recycled_id():
    sd = _sd()
    a = Image.open(os.path.join(STATUS, 'IDLE', 'IDLE1.bmp'))
    first = sd.color_sprite(a)
    assert sd.color_sprite(a) is first                     # cached
    # A different image must never be served another frame's sprite, even
    # when Python hands it the id of an image that has since been freed.
    seen = set()
    for path in sorted(glob.glob(os.path.join(STATUS, 'SSHBruteforce', '*[0-9].bmp')))[:6]:
        sprite = sd.color_sprite(Image.open(path))
        seen.add(sprite.tobytes())
    assert len(seen) > 1


def test_no_colour_version_for_plain_1bit_art():
    sd = _sd()
    assert sd.color_sprite(Image.new('1', (78, 78), 255)) is None
    sd.imagegen = None
    assert sd.color_sprite() is None


# ── the LCD main screen ─────────────────────────────────────────────────────

@pytest.mark.parametrize('gender', ['male', 'female'])
def test_lcd_main_screen_is_colour_with_the_colour_character(gender):
    sd = _sd(gender)
    img = _main_screen(_display(sd))
    assert img.mode == 'RGB'
    assert img.getpixel((60, 100)) == display._WD_COLORS['bg']      # dark theme
    # The character corner holds real colour art, not a white box or a stencil.
    corner = img.crop((128 - 50, 128 - 48, 127, 127))
    assert len(corner.getcolors(maxcolors=100000)) > 150
    assert sum(1 for p in _px(corner) if min(p) > 240) < 0.2 * corner.width * corner.height
    # Stat icons are tinted, each row in several different hues.
    icons = img.crop((2, 20, 126, 52))
    saturated = {p for p in _px(icons) if max(p) - min(p) > 80}
    assert len(saturated) > 6


def test_lcd_colour_can_be_switched_off():
    sd = _sd()
    img = _main_screen(_display(sd, lcd_color=False))
    assert img.mode == '1'


@pytest.mark.parametrize('epd', ['epd2in13_V4', 'epd2in7_V2', 'ssd1306', 'gc9a01'])
def test_other_panels_stay_1bit(epd):
    sd = _sd()
    d = _display(sd, epd_type=epd)
    assert d._lcd_color_panel(128, 128) is False
    assert _main_screen(d).mode == '1'


def test_1bit_main_screen_is_unchanged_by_the_colour_path():
    """On a 1-bit canvas every theme colour must collapse to black ink and the
    character must be the ordinary frame."""
    sd = _sd()
    d = _display(sd, lcd_color=False)
    img = _main_screen(d)
    assert d._wd_c(ImageDraw.Draw(img), 'title') == 0
    assert d._color_character(img, sd.imagegen, 46) is None
    assert img.histogram()[0] > 500          # ink was drawn


@pytest.mark.parametrize('gender', ['male', 'female'])
def test_wardriving_viking_page_shows_the_colour_character(gender):
    sd = _sd(gender)
    d = _display(sd)
    img = Image.new('RGB', (128, 128), display._WD_COLORS['bg'])
    d._render_wd_compact_viking(img, ImageDraw.Draw(img), {})
    band = img.crop((4, 4, 124, 106))
    assert len(band.getcolors(maxcolors=100000)) > 300
    # Switched off, the page keeps the 1-bit viking.
    d.config['wardriving_lcd_color'] = False
    assert d._wd_color_panel(128, 128) is False


@pytest.mark.parametrize('page_attr', ['_render_network_page', '_render_vuln_page',
    '_render_discovered_page', '_render_advanced_page', '_render_traffic_page'])
def test_info_pages_render_in_colour_on_the_lcd(page_attr):
    """The carousel info pages use the dark theme with a gold title and no outer
    border on the colour LCD, and stay 1-bit black on any other panel."""
    sd = _sd()
    d = _display(sd)
    d.render_sx = d.render_sy = 1.0
    d._get_cached_page_data = lambda *a, **k: None
    d._fit_font = lambda font_file, font, text, avail: font
    d._dbm_to_quality = lambda x: 50
    sd.networkkbnbr = 3
    # Colour LCD: RGB dark canvas, gold title row, no edge-hugging border.
    img = Image.new('RGB', (128, 128), display._WD_COLORS['bg'])
    getattr(d, page_attr)(img, ImageDraw.Draw(img))
    assert img.getpixel((64, 100)) == display._WD_COLORS["bg"]
    title_band = img.crop((2, 2, 126, 20))
    gold = sum(1 for p in _px(title_band) if p[0] > 150 and p[1] > 110 and p[2] < 120)
    assert gold > 20, 'expected a gold title'
    # No outer border: the first column and row are background, not a frame line.
    assert all(img.getpixel((0, y)) == display._WD_COLORS['bg'] for y in range(20, 108))
    assert all(img.getpixel((x, 127)) == display._WD_COLORS['bg'] for x in range(128))
    # Same page on a 1-bit canvas is plain black ink (other panels unchanged).
    one = Image.new('1', (128, 128), 255)
    getattr(d, page_attr)(one, ImageDraw.Draw(one))
    assert one.mode == '1' and one.histogram()[0] > 80
