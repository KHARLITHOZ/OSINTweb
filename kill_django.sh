#!/usr/bin/env bash
# kill_django.sh — limpia procesos Django zombie y locks SQLite
# Uso: ./kill_django.sh

set -euo pipefail

DB="$(dirname "$0")/db.sqlite3"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${YELLOW}[*] Escaneando procesos Django/runserver...${NC}"

# PIDs activos del servidor actual (los que queremos preservar si pasamos --preserve-active)
ZOMBIE_PIDS=$(ps aux | awk '/manage\.py|runserver/ && !/grep/ && $8 ~ /^T/' | awk '{print $2}')
ALL_PIDS=$(ps aux | awk '/manage\.py|runserver/ && !/grep/' | awk '{print $2}')

if [[ -z "$ALL_PIDS" ]]; then
    echo -e "${GREEN}[✓] No hay procesos Django activos.${NC}"
else
    echo -e "${YELLOW}[*] Procesos encontrados:${NC}"
    ps -o pid,stat,cmd -p $ALL_PIDS 2>/dev/null || true

    if [[ -n "$ZOMBIE_PIDS" ]]; then
        echo -e "${RED}[!] Procesos en estado T (zombie/stopped): $ZOMBIE_PIDS${NC}"
        echo -e "${YELLOW}[*] Enviando SIGKILL a zombies...${NC}"
        kill -9 $ZOMBIE_PIDS 2>/dev/null && echo -e "${GREEN}[✓] Zombies eliminados.${NC}" || true
    fi
fi

echo ""
echo -e "${YELLOW}[*] Verificando locks sobre db.sqlite3...${NC}"

if [[ ! -f "$DB" ]]; then
    echo -e "${YELLOW}[~] db.sqlite3 no encontrada en $DB${NC}"
else
    LOCKS=$(lsof "$DB" 2>/dev/null || true)
    if [[ -n "$LOCKS" ]]; then
        echo -e "${RED}[!] Procesos con lock sobre la DB:${NC}"
        echo "$LOCKS"
        LOCK_PIDS=$(echo "$LOCKS" | awk 'NR>1 {print $2}' | sort -u)
        echo ""
        echo -e "${YELLOW}[*] ¿Matar estos procesos? [s/N]: ${NC}"
        read -r confirm
        if [[ "$confirm" =~ ^[sS]$ ]]; then
            kill -9 $LOCK_PIDS 2>/dev/null && echo -e "${GREEN}[✓] Procesos con lock eliminados.${NC}" || true
        else
            echo -e "${YELLOW}[~] Skipped. DB puede seguir bloqueada.${NC}"
        fi
    else
        echo -e "${GREEN}[✓] db.sqlite3 libre — sin locks.${NC}"
    fi
fi

echo ""
echo -e "${YELLOW}[*] Estado final de procesos Django:${NC}"
REMAINING=$(ps aux | grep -E 'manage\.py|runserver' | grep -v grep || true)
if [[ -z "$REMAINING" ]]; then
    echo -e "${GREEN}[✓] Sin procesos Django activos.${NC}"
else
    echo "$REMAINING" | awk '{print "  PID="$2, "STAT="$8, $11, $12}'
fi

echo ""
echo -e "${GREEN}[✓] Listo. Puedes lanzar: python manage.py runserver${NC}"
