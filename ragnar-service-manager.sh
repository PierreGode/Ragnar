#!/bin/bash
# Ragnar Service Manager
# Helper script for managing ragnar-core and ragnar-web services

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Functions
show_status() {
    echo -e "${BLUE}=== Ragnar Services Status ===${NC}"
    echo ""
    echo -e "${GREEN}Core Service (ragnar.service):${NC}"
    systemctl status ragnar.service --no-pager -l
    echo ""
    echo -e "${GREEN}Web Service (ragnar-web.service):${NC}"
    systemctl status ragnar-web.service --no-pager -l
}

start_services() {
    echo -e "${BLUE}Starting Ragnar services...${NC}"
    sudo systemctl start ragnar.service
    sudo systemctl start ragnar-web.service
    echo -e "${GREEN}✓ Services started${NC}"
    show_status
}

stop_services() {
    echo -e "${BLUE}Stopping Ragnar services...${NC}"
    sudo systemctl stop ragnar-web.service
    sudo systemctl stop ragnar.service
    echo -e "${GREEN}✓ Services stopped${NC}"
}

restart_services() {
    echo -e "${BLUE}Restarting Ragnar services...${NC}"
    sudo systemctl restart ragnar.service
    sudo systemctl restart ragnar-web.service
    echo -e "${GREEN}✓ Services restarted${NC}"
    show_status
}

restart_core() {
    echo -e "${BLUE}Restarting core service only...${NC}"
    sudo systemctl restart ragnar.service
    echo -e "${GREEN}✓ Core service restarted${NC}"
    systemctl status ragnar.service --no-pager -l
}

restart_web() {
    echo -e "${BLUE}Restarting web service only...${NC}"
    sudo systemctl restart ragnar-web.service
    echo -e "${GREEN}✓ Web service restarted${NC}"
    systemctl status ragnar-web.service --no-pager -l
}

show_logs() {
    local service=$1
    if [ -z "$service" ]; then
        echo -e "${BLUE}Showing logs for both services (press Ctrl+C to exit):${NC}"
        sudo journalctl -u ragnar.service -u ragnar-web.service -f
    elif [ "$service" == "core" ]; then
        echo -e "${BLUE}Showing core service logs (press Ctrl+C to exit):${NC}"
        sudo journalctl -u ragnar.service -f
    elif [ "$service" == "web" ]; then
        echo -e "${BLUE}Showing web service logs (press Ctrl+C to exit):${NC}"
        sudo journalctl -u ragnar-web.service -f
    fi
}

show_help() {
    echo -e "${BLUE}Ragnar Service Manager${NC}"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  status          - Show status of both services"
    echo "  start           - Start both services"
    echo "  stop            - Stop both services"
    echo "  restart         - Restart both services"
    echo "  restart-core    - Restart core service only"
    echo "  restart-web     - Restart web service only"
    echo "  logs            - Show logs for both services"
    echo "  logs-core       - Show core service logs"
    echo "  logs-web        - Show web service logs"
    echo "  help            - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 status"
    echo "  $0 restart-web"
    echo "  $0 logs-core"
}

# Main
case "$1" in
    status)
        show_status
        ;;
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    restart-core)
        restart_core
        ;;
    restart-web)
        restart_web
        ;;
    logs)
        show_logs
        ;;
    logs-core)
        show_logs core
        ;;
    logs-web)
        show_logs web
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}Error: Unknown command '$1'${NC}"
        echo ""
        show_help
        exit 1
        ;;
esac
