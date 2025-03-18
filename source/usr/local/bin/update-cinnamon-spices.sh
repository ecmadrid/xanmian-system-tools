#!/bin/bash

# Directorio donde se almacenan los applets de Cinnamon
APPLET_DIR="$HOME/.local/share/cinnamon/applets/SpicesUpdate@claudiux"
DOWNLOAD_URL="https://cinnamon-spices.linuxmint.com/uploads/applets/8JSI-KGZY-ADX8.zip"
TEMP_ZIP="/tmp/spices-update.zip"

# Verificar si Spices Update está instalado
if [ ! -d "$APPLET_DIR" ]; then
    echo "El applet Spices Update no está instalado. Descargándolo..."
    if ! wget -O "$TEMP_ZIP" "$DOWNLOAD_URL" 2>/dev/null; then
        echo "Error: No se pudo descargar Spices Update." >&2
        exit 1
    fi
    if ! unzip -q "$TEMP_ZIP" -d "$HOME/.local/share/cinnamon/applets/"; then
        echo "Error: No se pudo descomprimir el archivo." >&2
        rm -f "$TEMP_ZIP"
        exit 1
    fi
    rm -f "$TEMP_ZIP"
    echo "Spices Update instalado correctamente."
fi

# Asegurarse de que el applet esté habilitado
ENABLED_APPLETS=$(gsettings get org.cinnamon enabled-applets)
if [[ ! "$ENABLED_APPLETS" =~ "SpicesUpdate@claudiux" ]]; then
    echo "Habilitando Spices Update..."
    NEW_APPLETS=$(echo "$ENABLED_APPLETS" | sed 's/]$/, "panel1:right:0:SpicesUpdate@claudiux:0"]/')
    if ! gsettings set org.cinnamon enabled-applets "$NEW_APPLETS"; then
        echo "Error: No se pudo habilitar el applet." >&2
        exit 1
    fi
fi

# Forzar actualización de Spices
echo "Actualizando Spices..."
if ! dbus-send --session --dest=org.Cinnamon --type=method_call /org/Cinnamon org.Cinnamon.RefreshSpices 2>/dev/null; then
    echo "Advertencia: No se pudo forzar la actualización de Spices." >&2
fi

echo "Proceso completado."
exit 0
