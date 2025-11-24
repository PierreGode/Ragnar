# Ragnar Service Separation Architecture

## Overview

Ragnar has been refactored to separate the web UI from the core orchestrator/scanner functionality. This separation provides several benefits:

- **Reduced CPU usage**: The web server no longer blocks the orchestrator
- **Improved stability**: Web UI crashes don't affect core functionality
- **Lower memory pressure**: Services can be restarted independently
- **Better debugging**: Logs are separated by service
- **Independent scaling**: Each service can have different resource limits

## Architecture

```text
┌───────────────────┐       ┌──────────────────────┐
│   ragnar-core     │       │     ragnar-web       │
│ (scanner, logic)  │ <──>  │ (Flask/FastAPI)      │
└───────────────────┘       └──────────────────────┘
        │                               │
        │ writes                        │ reads
        ▼                               ▼
     sqlite.db                    sqlite.db / cache
```

## Services

### `ragnar.service` (Core)
- **Functionality**: Network scanning, orchestrator, display management
- **Script**: `/home/ragnar/Ragnar/Ragnar.py`
- **Resources**: MemoryMax=384M, MemoryHigh=320M
- **Auto-start**: Yes
- **Restart**: Always

### `ragnar-web.service` (Web UI)
- **Functionality**: Flask/SocketIO web dashboard on port 8000
- **Script**: `/home/ragnar/Ragnar/ragnar_web.py`
- **Resources**: MemoryMax=256M, MemoryHigh=200M
- **Auto-start**: Yes (after ragnar.service)
- **Restart**: Always (10s delay)

## Service Management

### Start/Stop Services

```bash
# Start both services
sudo systemctl start ragnar ragnar-web

# Stop both services
sudo systemctl stop ragnar ragnar-web

# Restart individual services
sudo systemctl restart ragnar        # Core only
sudo systemctl restart ragnar-web    # Web UI only

# Check status
sudo systemctl status ragnar
sudo systemctl status ragnar-web
```

### View Logs

```bash
# Core service logs
sudo journalctl -u ragnar -f

# Web service logs
sudo journalctl -u ragnar-web -f

# Both services
sudo journalctl -u ragnar -u ragnar-web -f
```

### Enable/Disable Auto-start

```bash
# Enable auto-start
sudo systemctl enable ragnar ragnar-web

# Disable auto-start
sudo systemctl disable ragnar ragnar-web
```

## Data Flow

1. **Core → Database**: Ragnar core writes scan results, vulnerabilities, and attack data to SQLite
2. **Database → Web**: Web UI reads from SQLite and serves data via HTTP/WebSocket
3. **Web → Core**: Web UI can trigger actions (start/stop orchestrator) via shared_data

## Communication

Services communicate through:
- **Shared SQLite database**: Primary data store
- **Shared Python objects**: `shared_data` singleton
- **File system**: Configuration files, logs, results

## Troubleshooting

### Web UI not accessible
```bash
# Check if service is running
sudo systemctl status ragnar-web

# Check if port 8000 is in use
sudo lsof -i :8000

# Restart web service
sudo systemctl restart ragnar-web
```

### Core not scanning
```bash
# Check if service is running
sudo systemctl status ragnar

# Check orchestrator status in web UI or logs
sudo journalctl -u ragnar -n 50
```

### High memory usage
```bash
# Check memory usage per service
systemctl status ragnar
systemctl status ragnar-web

# Restart services to free memory
sudo systemctl restart ragnar ragnar-web
```

## Migration from Old Architecture

If upgrading from the old single-service architecture, you have two options:

### Option 1: Automated Migration (Recommended)
Use the migration script to automatically update your installation:

```bash
cd /home/ragnar/Ragnar
sudo git pull  # Get the latest updates
sudo ./migrate_to_separated_services.sh
```

The script will:
- Stop the old single service
- Create new service files with resource limits
- Enable and start both services
- Verify everything is working

### Option 2: Manual Migration
1. **Stop old service**: `sudo systemctl stop ragnar`
2. **Pull updates**: `cd /home/ragnar/Ragnar && sudo git pull`
3. **Reinstall**: Run `sudo ./install_ragnar.sh` to create new service files
4. **Reboot**: `sudo reboot` to start both services

### Option 3: Fresh Install
If you prefer a clean slate:
```bash
cd /home/ragnar/Ragnar
sudo ./uninstall_ragnar.sh  # Remove old installation
sudo ./install_ragnar.sh    # Fresh install with new architecture
```

## Benefits

### Before (Single Service)
- ❌ Web UI blocked by long-running scans
- ❌ High CPU usage (50-70% idle)
- ❌ Risk of SIGKILL due to memory pressure
- ❌ Difficult to debug web vs core issues

### After (Separated Services)
- ✅ Web UI always responsive
- ✅ Lower CPU usage per service
- ✅ Independent restart capability
- ✅ Clear separation of concerns
- ✅ Better resource management

## Configuration

Both services read from:
- `/home/ragnar/Ragnar/config/config.json`
- `/home/ragnar/Ragnar/.env`

The `websrv` config option is now only used by `ragnar-web.service`.

## Future Enhancements

Potential improvements to the architecture:
- [ ] IPC mechanism for core to trigger web UI updates
- [ ] Separate database connections for read/write
- [ ] API-based communication between services
- [ ] Containerization (Docker/Podman)
