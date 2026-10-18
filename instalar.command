#!/bin/bash
# vidaas-pjeoffice-mac: instala, testa ou remove a ponte VIDaaS -> PJeOffice em qualquer Mac.
#
# Uso (dois cliques neste arquivo, ou no Terminal):
#   bash instalar.command            instala ou repara
#   bash instalar.command --testar   instala e faz uma assinatura MD5 de teste (como no login do PJe)
#   bash instalar.command --remover  remove a ponte e restaura a configuracao anterior do PJeOffice

set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/Library/VidaasBridge"
LIB="$DEST/libvidaasbridge.dylib"
CONF="$HOME/.pjeoffice-pro/pjeoffice-pro.config"
BACKUP="$DEST/pjeoffice-pro.config.antes-da-ponte"
MODO="${1:-}"

ok()   { echo "  [ok] $*"; }
info() { echo "  ... $*"; }
erro() { echo "  [ERRO] $*"; }
fim()  { [ -t 0 ] && { echo; read -r -p "Pressione Enter para fechar..." _; }; exit "$1"; }

echo "== Ponte VIDaaS -> PJeOffice (macOS) =="

# ---------- remover ----------
if [ "$MODO" = "--remover" ]; then
  pkill -f "pjeoffice-pro" 2>/dev/null && sleep 2
  if [ -f "$BACKUP" ]; then cp "$BACKUP" "$CONF" && ok "configuracao anterior do PJeOffice restaurada"
  elif [ -f "$CONF" ]; then sed -i '' "\#^list\.a3=$LIB#d" "$CONF" && ok "ponte retirada da configuracao do PJeOffice"; fi
  rm -rf "$DEST" && ok "driver removido"
  fim 0
fi

# ---------- localizar programas ----------
APP=""
for a in "/Applications/pjeoffice-pro.app" "$HOME/Applications/pjeoffice-pro.app"; do [ -d "$a" ] && APP="$a" && break; done
CPU=$(uname -m)
if [ -z "$APP" ]; then
  [ "$CPU" = "arm64" ] && pkg="mac_a64" || pkg="mac_x64"
  erro "PJeOffice Pro nao encontrado. Baixe o instalador '$pkg' em https://pje-office.pje.jus.br/pro/ (pagina oficial do CNJ), instale e rode este script de novo."
  fim 1
fi
ok "PJeOffice Pro encontrado em $APP"
if [ ! -d "/Applications/VidaaS.app" ]; then
  erro "VIDaaS Connect nao encontrado. Instale-o pelo site da Valid Certificadora, entre com seu certificado e rode este script de novo."
  fim 1
fi
ok "VIDaaS Connect encontrado"

# ---------- driver ----------
mkdir -p "$DEST"
compilou=0
if command -v clang >/dev/null 2>&1 && clang --version >/dev/null 2>&1 && [ -f "$DIR/src/vidaasbridge.m" ]; then
  info "compilando o driver a partir do codigo-fonte"
  if clang -dynamiclib -arch arm64 -arch x86_64 -fobjc-arc -O2 -Wno-deprecated-declarations \
       -mmacosx-version-min=12.0 -framework Foundation -framework Security \
       -o "$DEST/libvidaasbridge.dylib.novo" "$DIR/src/vidaasbridge.m"; then
    mv "$DEST/libvidaasbridge.dylib.novo" "$LIB"; compilou=1; ok "driver compilado"
  fi
fi
if [ $compilou -eq 0 ]; then
  if [ -f "$DIR/dist/libvidaasbridge.dylib" ]; then
    cp "$DIR/dist/libvidaasbridge.dylib" "$LIB"; xattr -c "$LIB" 2>/dev/null
    ok "driver pronto copiado de dist/ (sem compilador neste Mac)"
  else
    erro "nao foi possivel compilar nem achar dist/libvidaasbridge.dylib. Instale as ferramentas com: xcode-select --install"
    fim 1
  fi
fi
codesign -s - -f "$LIB" >/dev/null 2>&1
ok "driver instalado em $LIB"

# ---------- configurar o PJeOffice ----------
pkill -f "pjeoffice-pro" 2>/dev/null && { info "fechando o PJeOffice"; sleep 3; }
mkdir -p "$(dirname "$CONF")"
[ -f "$CONF" ] && [ ! -f "$BACKUP" ] && cp "$CONF" "$BACKUP"
if [ -f "$CONF" ] && grep -q "^list\.a3=" "$CONF"; then
  sed -i '' "s#^list\.a3=.*#list.a3=$LIB#" "$CONF"
else
  echo "list.a3=$LIB" >> "$CONF"
fi
ok "PJeOffice configurado para usar a ponte (configuracao anterior guardada em $BACKUP)"

# ---------- VIDaaS e certificado ----------
pgrep -x VidaaS >/dev/null || { info "abrindo o VIDaaS Connect"; open -g -a VidaaS; sleep 5; }
achou=0
for i in $(seq 1 15); do
  system_profiler SPSmartCardsDataType 2>/dev/null | grep -q "private RSA" && { achou=1; break; }
  [ "$i" -eq 3 ] && { info "reiniciando o VIDaaS Connect"; pkill -x VidaaS; pkill -f vidaasConnectToken; sleep 2; open -g -a VidaaS; }
  sleep 2
done
[ $achou -eq 1 ] && ok "certificado VIDaaS visivel no macOS" || erro "nenhum certificado VIDaaS visivel. Abra o VIDaaS Connect e confira se o seu certificado aparece nele."

# ---------- teste ----------
if [ $achou -eq 1 ] && command -v clang >/dev/null 2>&1 && clang --version >/dev/null 2>&1; then
  T="$(mktemp -d)"
  if clang -O1 -w -o "$T/teste" -I"$DIR/tools" "$DIR/tools/teste-pkcs11.c" -framework Foundation -framework Security 2>/dev/null; then
    if [ "$MODO" = "--testar" ]; then
      info "assinatura MD5 de teste (pode pedir aprovacao no VIDaaS)"
      (cd "$T" && P11LIB="$LIB" ./teste 5 2>&1) | grep -q "sign rv=0" && ok "assinatura MD5 de teste funcionou" || erro "assinatura de teste falhou; veja ~/Library/Logs/VidaasBridge.log"
    else
      (cd "$T" && P11LIB="$LIB" ./teste 2>&1) | grep -A1 "cls=3" | grep -q "found [1-9]" && ok "a ponte encontra a chave do certificado" || erro "a ponte nao encontrou a chave; veja ~/Library/Logs/VidaasBridge.log"
    fi
  fi
  rm -rf "$T"
fi

open -a "$APP" && ok "PJeOffice aberto"
echo
echo "Pronto. No PJe, clique em 'Certificado Digital'. Registro da ponte: ~/Library/Logs/VidaasBridge.log"
fim 0
