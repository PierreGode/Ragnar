# Levels, Points & Ranks

Ragnar rewards activity with **points**, which roll up into a **level**, a Norse
**rank**, and — once you hit the ceiling — **renown**. Progress is persistent and
lives in `data/gamification.json`. The dashboard **Level card** shows the level,
the current rank, a progress bar to the next level, and (on hover) a breakdown of
where the points came from.

## The curve

The level formula is deliberately simple and **unchanged** from earlier releases,
so no existing progress is ever lost:

```
level = 1 + total_points // 200      (capped at level 1000)
```

Every 200 points is one level. Level **1000** is the cap (see *Renown* below).
`total_points` only ever grows, and the formula is identical to the old one for
every point value below the cap — upgrading never moves anyone's level.

## Ranks

The numeric level maps to a Norse rank, shown next to the level on the dashboard:

| Rank        | Levels     |
|-------------|------------|
| Thrall      | 1 – 9      |
| Karl        | 10 – 24    |
| Hersir      | 25 – 49    |
| Jarl        | 50 – 99    |
| Konungr     | 100 – 199  |
| Berserkr    | 200 – 349  |
| Einherjar   | 350 – 599  |
| Jötunn      | 600 – 999  |
| **Ragnar**  | **1000**   |

Reaching the cap makes you **Ragnar** — the pinnacle.

## Renown

Points earned **after** level 1000 aren't wasted: every `10000` points past the
cap is one **renown star** (`★`), shown beside your points. There is no ceiling on
renown, so there's always something to climb toward.

## Where points come from

### Snapshot sources
Counted from your running totals; each new item is worth a fixed number of points.

| Source              | Points each |
|---------------------|-------------|
| New MAC address     | 15          |
| Credential          | 25          |
| Data file           | 10          |
| Zombie              | 40          |
| Vulnerability       | 20          |
| Attack              | 30          |
| Open port           | 2           |
| Network scanned     | 5           |
| Host discovered     | 3           |

### Event sources
Awarded as activity happens, via `SharedData.award_event_points(event_type, count)`.

| Event                     | Points each |
|---------------------------|-------------|
| Defense detection — critical | 15       |
| Defense detection — high     | 10       |
| Defense detection — medium   | 5        |
| Defense detection — low      | 2        |
| Defense detection — info     | 1        |
| Wardrive network             | 4        |
| GPS fix                      | 1        |
| RF capture                   | 3        |
| RF decode                    | 2        |
| ADS-B contact                | 1        |
| BT/BLE/Zigbee device         | 2        |
| Mesh peer                    | 20       |
| Scan completed               | 8        |

**Defense detections** are wired through the Watchtower poll loop, so every
standalone Watch/Guard detector and the WiFi-Defense WIDS feeds points in one
place, scaled by severity. **Mesh peers** are awarded once per peer id when the
mesh poll first sees a new Ragnar unit. The remaining event types are available to
any subsystem through `award_event_points(...)`; wire a call at the point a new
capture/decode/contact is confirmed to start rewarding it.

## Backward compatibility

`data/gamification.json` carries a `version`. On first load after upgrading, a
`v1 → v2` migration runs that:

- **Preserves `total_points` and `level` exactly** — nobody's level changes.
- **Baselines the new snapshot sources** (attacks, ports, networks, hosts) at
  their current lifetime totals, so you get **no retroactive point windfall** —
  only activity from the upgrade onward earns from those sources.

## API

`GET /api/gamification` returns the full summary the dashboard uses:

```json
{
  "level": 58,
  "points": 11415,
  "max_level": 1000,
  "at_cap": false,
  "points_into_level": 15,
  "points_per_level": 200,
  "points_to_next": 185,
  "progress_pct": 7,
  "rank": "Jarl",
  "next_rank": "Konungr",
  "next_rank_level": 100,
  "renown": 0,
  "breakdown": [ { "source": "Networks scanned", "count": 300, "points": 1500 } ]
}
```

## Tuning

All point values, the level cap, the renown cost, and the rank ladder are plain
attributes set in `SharedData.__init__` (`points_per_*`, `event_point_values`,
`max_level`, `renown_points_per_star`, `rank_ladder`). The dashboard mirrors the
curve constants and rank ladder in `web/scripts/ragnar_modern.js`
(`renderLevelProgress`) — keep the two in sync if you retune.
