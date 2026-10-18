# vidaas-pjeoffice-mac

Faz o **certificado em nuvem VIDaaS** (Valid) funcionar no **PJeOffice Pro** em **qualquer Mac**, com Apple Silicon ou Intel. Assim você consegue entrar no PJe e assinar com o VIDaaS no macOS.

> Projeto independente, sem relação com a Valid Certificadora, o CNJ ou os tribunais. Use por sua conta e risco.

## O problema

No Mac, o VIDaaS Connect com o PJeOffice Pro falha de três formas:

1. **O driver PKCS#11 da Valid** (`/Library/Frameworks/libCryptoValid.dylib`) só existe para Intel, mesmo no pacote "Apple Silicon". Além disso, ele derruba o PJeOffice dentro de `C_FindObjectsInit` (`std::length_error`).
2. **O login do PJe** (sso.cloud.pje.jus.br) pede uma assinatura **MD5withRSA**. A extensão do VIDaaS Connect para macOS (CryptoTokenKit) recusa o DigestInfo MD5 completo e devolve o erro `-4`. Ela só aceita MD5 quando recebe **o resumo puro de 16 bytes** no modo `kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw`.
3. **A extensão do VIDaaS às vezes trava** ao abrir a janela de aprovação. Isso foi visto no macOS 26. Depois do travamento, o certificado some do sistema até o app ser reaberto.

## A solução

`libvidaasbridge.dylib` é um módulo **PKCS#11** pequeno e universal (arm64 + x86_64) que:

- entrega ao PJeOffice os certificados VIDaaS que o macOS já enxerga pelo CryptoTokenKit, inclusive mais de um (e-CPF e e-CNPJ);
- converte cada assinatura para o formato que o VIDaaS aceita:
  - `CKM_MD5_RSA_PKCS` e `CKM_RSA_PKCS` com DigestInfo MD5 vão como resumo MD5 de 16 bytes no modo *DigestPKCS1v15Raw*;
  - SHA-1, SHA-256, SHA-384 e SHA-512 vão pelos algoritmos *DigestPKCS1v15SHAxxx*;
- reinicia o VIDaaS Connect sozinho e tenta de novo quando a extensão trava.

Nenhum dado sai do seu Mac por causa da ponte. A assinatura continua sendo feita pela nuvem do VIDaaS, pelo app oficial da Valid.

## Requisitos

- macOS 12 ou mais recente, em Mac Apple Silicon ou Intel.
- **VIDaaS Connect** instalado e com o seu certificado aparecendo nele.
- **PJeOffice Pro** instalado, de preferência a versão do seu processador, baixada da [página oficial](https://pje-office.pje.jus.br/pro/): `mac_a64` para Apple Silicon e `mac_x64` para Intel.
- Opcional: as ferramentas de linha de comando (`xcode-select --install`), para compilar a partir do código-fonte. Sem elas, o instalador usa o driver já compilado em `dist/`.

## Instalação

1. Baixe este repositório: botão **Code → Download ZIP**, depois descompacte.
2. Dê dois cliques em **`instalar.command`**. Se o macOS bloquear, clique com o botão direito → **Abrir**. Também dá para rodar no Terminal:

```bash
bash instalar.command
```

O instalador:
- confere se o PJeOffice e o VIDaaS estão instalados;
- compila ou copia o driver para `~/Library/VidaasBridge/`;
- configura o PJeOffice (`~/.pjeoffice-pro/pjeoffice-pro.config`, linha `list.a3`) e guarda a configuração anterior;
- confere se o certificado VIDaaS aparece no macOS;
- testa o driver e abre o PJeOffice.

Depois disso, entre no PJe e clique em **Certificado Digital**.

### Outras opções

```bash
bash instalar.command --testar    # instala e faz uma assinatura MD5 de teste, como no login do PJe
bash instalar.command --remover   # remove a ponte e restaura a configuração anterior do PJeOffice
```

## Problemas

- Registro da ponte: `~/Library/Logs/VidaasBridge.log`. Ele contém o nome do titular do certificado, então não publique esse arquivo sem apagar esses dados.
- Se o PJeOffice for atualizado ou reinstalado, rode o `instalar.command` de novo.
- Cada assinatura leva de 8 a 10 segundos, que é o tempo da nuvem do VIDaaS.
- O instalador troca a lista de drivers A3 do PJeOffice pela ponte. Se você usa também um token físico no mesmo Mac, adicione o driver dele de novo nas configurações do PJeOffice.

## Estrutura

| Caminho | O que é |
|---|---|
| `src/vidaasbridge.m` | código do módulo PKCS#11 (Objective-C) |
| `dist/libvidaasbridge.dylib` | módulo já compilado (universal) |
| `tools/teste-pkcs11.c` | programa de teste: lista objetos e assina (`P11LIB=... ./teste 5` para MD5) |
| `instalar.command` | instalador, teste e remoção |

Para compilar manualmente:

```bash
clang -dynamiclib -arch arm64 -arch x86_64 -fobjc-arc -O2 -Wno-deprecated-declarations -mmacosx-version-min=12.0 -framework Foundation -framework Security -o libvidaasbridge.dylib src/vidaasbridge.m
```

## Testado em

- MacBook com Apple A18 Pro, macOS 26.5.1, VIDaaS Connect 1.4.6 e PJeOffice Pro 2.5.16 (arm64 e x86_64): login no PJe TJMG por certificado.

Relatos de outros tribunais, Macs e versões são bem-vindos nas *Issues*.

## Você chegou aqui procurando por...

Este projeto resolve, no Mac, problemas como:

- **"Não foi possível encontrar o PJe Office"**, ou o PJeOffice abre mas **não lista o certificado VIDaaS**
- **"Não foi possível validar seu Certificado Digital"** no login do PJe
- **PJeOffice Pro fecha sozinho** (trava) ao ler o certificado VIDaaS no macOS
- `libCryptoValid.dylib` não carrega no PJeOffice para **Apple Silicon (M1, M2, M3, M4, A18 Pro)**: "incompatible architecture" ou "mach-o file, but is an incompatible architecture"
- **VIDaaS Connect no Mac** não funciona no PJe: erro `CryptoTokenKit Code=-4`, extensão `vidaasConnectToken` travando, certificado sumindo do Acesso às Chaves
- Login com **certificado em nuvem** (VIDaaS, Valid) no **PJe 1º e 2º grau**, **PDPJ** e `sso.cloud.pje.jus.br`, com assinatura **MD5withRSA**
- Configurar **dispositivo A3** ou **driver PKCS#11** no PJeOffice Pro no macOS

Palavras-chave: PJe, PJeOffice, PJe Office Pro, VIDaaS, VIDaaS Connect, Valid Certificadora, certificado digital em nuvem, e-CPF A3, e-CNPJ A3, macOS, Mac, MacBook, Apple Silicon, M1, M2, M3, M4, Intel, Rosetta, PKCS#11, CryptoTokenKit, TJMG, PJe TJMG, CNJ, assinatura digital, ICP-Brasil, advogado.

Testado no PJe do TJMG. Outros tribunais que usam o mesmo login do PJe (sso.cloud.pje.jus.br) devem funcionar igual. Confirmações são bem-vindas nas *Issues*.

## English summary

macOS PKCS#11 bridge that makes the Brazilian **VIDaaS** cloud certificate (Valid Certificadora) work with **PJeOffice Pro**, the signer used by Brazil's **PJe** court system, on Apple Silicon and Intel Macs. It exposes the VIDaaS identities that macOS publishes through CryptoTokenKit as a universal PKCS#11 module. It fixes the PJe SSO **MD5withRSA** login: VIDaaS only accepts MD5 as a bare 16-byte digest with `kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw`. It also replaces Valid's crashing, Intel-only `libCryptoValid.dylib`, and restarts VIDaaS Connect when its token extension crashes.

## Licença

MIT. Veja [LICENSE](LICENSE).
