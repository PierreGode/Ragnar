# Ragnar Data Synchronization Fix

## Problem
Dashboard, NetKB, and E-paper display were showing different vulnerability counts and statistics because they were reading from different data sources without synchronization.

## Root Cause
- **Dashboard** (`/api/dashboard/stats`) - Count vulnerabilities from files in `vulnerabilities_dir`
- **NetKB** (`/api/netkb/data`) - Count vulnerabilities from files and show in entries
- **Main Status/E-paper** (`/api/status`) - Use `shared_data.vulnnbr` set by `display.py`
- **E-paper Display** - Use `shared_data.vulnnbr` directly

These different systems were not communicating with each other, causing inconsistent counts.

## Solution Implemented

### 1. Created Centralized Synchronization Functions

**`sync_vulnerability_count()`**
- Counts vulnerabilities from files in `vulnerabilities_dir`
- Updates `shared_data.vulnnbr` with the actual count
- Updates `livestatus.csv` file with synchronized count
- Used by all vulnerability-related endpoints

**`sync_all_counts()`**
- Synchronizes ALL statistics (targets, ports, vulnerabilities, credentials)
- Counts from actual scan result files in respective directories
- Updates all `shared_data` counters
- Updates `livestatus.csv` with all synchronized counts
- Ensures complete consistency across all data sources

### 2. Updated API Endpoints

**`/api/status`** (E-paper display data)
- Now calls `sync_all_counts()` before returning data
- Ensures e-paper display shows current counts

**`/api/dashboard/stats`** (Dashboard statistics)
- Now calls `sync_all_counts()` before returning data
- Simplified to only return synchronized `shared_data` values
- Removed redundant file counting logic

**`/api/netkb/data`** (NetKB statistics)
- Now calls `sync_all_counts()` before calculating statistics
- Uses synchronized `shared_data.vulnnbr` for vulnerability count display
- Ensures NetKB statistics panel shows correct counts

### 3. Added Periodic Synchronization

**`broadcast_status_updates()`**
- Added automatic synchronization every 20 seconds during WebSocket broadcasts
- Ensures all connected clients receive updated, synchronized data
- Keeps e-paper display current with latest counts

## Data Flow After Fix

```
File System Data Sources
         ↓
   sync_all_counts()
         ↓
   shared_data.* counters  ← Single source of truth
         ↓
┌────────────────────────────────────┐
│  Dashboard  │  NetKB  │  E-paper   │
│     API     │   API   │   Display  │
└────────────────────────────────────┘
```

## Benefits

1. **Consistency**: All displays now show the same counts
2. **Real-time**: Periodic synchronization ensures data stays current
3. **Reliability**: Single source of truth eliminates discrepancies
4. **Performance**: Reduced redundant file processing across endpoints
5. **Maintainability**: Centralized counting logic

## Files Modified

- `webapp_modern.py`: Added sync functions and updated all endpoints
- `SYNCHRONIZATION_FIX.md`: This documentation

## Testing

1. Check Dashboard → should show correct vulnerability count
2. Check NetKB → statistics panel should match dashboard
3. Check E-paper display → should match dashboard and NetKB
4. Add/remove vulnerability files → all displays should update consistently
5. Monitor WebSocket updates → counts should sync every 20 seconds

## Notes

- Synchronization runs automatically every 20 seconds via WebSocket broadcast
- All API endpoints now sync before returning data for immediate consistency
- `livestatus.csv` file is kept updated with all synchronized counts
- E-paper display automatically reflects changes since it uses `shared_data`