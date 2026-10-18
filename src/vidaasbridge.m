// VidaasBridge: modulo PKCS#11 que entrega os certificados VIDaaS (CryptoTokenKit do macOS)
// a programas como o PJeOffice, convertendo cada assinatura para o formato aceito pela
// extensao do VIDaaS Connect. MD5 vai como resumo puro de 16 bytes no modo DigestPKCS1v15Raw.
// Licenca MIT. Sem afiliacao com a Valid Certificadora nem com o CNJ.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#include <string.h>
#include <pthread.h>

typedef unsigned long CK_ULONG, CK_RV, CK_FLAGS, CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
  CK_MECHANISM_TYPE, CK_ATTRIBUTE_TYPE, CK_USER_TYPE, CK_STATE;
typedef unsigned char CK_BYTE, CK_BBOOL, CK_UTF8CHAR;
typedef struct { CK_BYTE major, minor; } CK_VERSION;
typedef struct { CK_ATTRIBUTE_TYPE type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_MECHANISM_TYPE mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_VERSION cryptokiVersion; CK_UTF8CHAR manufacturerID[32]; CK_FLAGS flags;
  CK_UTF8CHAR libraryDescription[32]; CK_VERSION libraryVersion; } CK_INFO;
typedef struct { CK_UTF8CHAR slotDescription[64]; CK_UTF8CHAR manufacturerID[32]; CK_FLAGS flags;
  CK_VERSION hardwareVersion, firmwareVersion; } CK_SLOT_INFO;
typedef struct { CK_UTF8CHAR label[32], manufacturerID[32], model[16]; CK_BYTE serialNumber[16]; CK_FLAGS flags;
  CK_ULONG ulMaxSessionCount, ulSessionCount, ulMaxRwSessionCount, ulRwSessionCount, ulMaxPinLen, ulMinPinLen,
  ulTotalPublicMemory, ulFreePublicMemory, ulTotalPrivateMemory, ulFreePrivateMemory;
  CK_VERSION hardwareVersion, firmwareVersion; CK_BYTE utcTime[16]; } CK_TOKEN_INFO;
typedef struct { CK_SLOT_ID slotID; CK_STATE state; CK_FLAGS flags; CK_ULONG ulDeviceError; } CK_SESSION_INFO;
typedef struct { CK_ULONG ulMinKeySize, ulMaxKeySize; CK_FLAGS flags; } CK_MECHANISM_INFO;
typedef CK_RV (*CK_FN)(void);
typedef struct { CK_VERSION version; CK_FN f[68]; } CK_FUNCTION_LIST;

#define CKR_OK 0x0
#define CKR_SLOT_ID_INVALID 0x3
#define CKR_GENERAL_ERROR 0x5
#define CKR_FUNCTION_FAILED 0x6
#define CKR_ARGUMENTS_BAD 0x7
#define CKR_ATTRIBUTE_TYPE_INVALID 0x12
#define CKR_DATA_INVALID 0x20
#define CKR_DEVICE_ERROR 0x30
#define CKR_FUNCTION_CANCELED 0x50
#define CKR_FUNCTION_NOT_SUPPORTED 0x54
#define CKR_KEY_HANDLE_INVALID 0x60
#define CKR_MECHANISM_INVALID 0x70
#define CKR_OBJECT_HANDLE_INVALID 0x82
#define CKR_OPERATION_ACTIVE 0x90
#define CKR_OPERATION_NOT_INITIALIZED 0x91
#define CKR_SESSION_HANDLE_INVALID 0xB3
#define CKR_USER_ALREADY_LOGGED_IN 0x100
#define CKR_BUFFER_TOO_SMALL 0x150
#define CKR_CRYPTOKI_NOT_INITIALIZED 0x190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x191
#define CK_UNAVAILABLE ((CK_ULONG)-1)

#define CKO_CERTIFICATE 1
#define CKO_PRIVATE_KEY 3
#define CKM_RSA_PKCS 0x1
#define CKM_MD5_RSA_PKCS 0x5
#define CKM_SHA1_RSA_PKCS 0x6
#define CKM_SHA256_RSA_PKCS 0x40
#define CKM_SHA384_RSA_PKCS 0x41
#define CKM_SHA512_RSA_PKCS 0x42

#define SLOT 1
#define MAXC 8          // certificados VIDaaS suportados (objetos: certificado = 2i+1, chave = 2i+2)
#define MAXS 64
#define TOKEN_PREFIX @"br.com.valid.vidaas"

static int g_init = 0;
static pthread_mutex_t g_mx = PTHREAD_MUTEX_INITIALIZER;
@interface VBCert : NSObject
@property NSData *cert, *ident, *label, *subject, *issuer, *serial, *mod, *exp;
@end
@implementation VBCert
@end
static NSMutableArray<VBCert *> *g_certs;

typedef struct { int open; int findActive; CK_ULONG findIdx, findN; CK_OBJECT_HANDLE found[2 * MAXC];
  int signActive; CK_MECHANISM_TYPE mech; int certIdx; CC_SHA512_CTX s512; CC_SHA256_CTX s256; CC_SHA1_CTX s1; CC_MD5_CTX m5;
  CFMutableDataRef buf; } Sess;
static Sess g_s[MAXS + 1];

static void logf_(NSString *fmt, ...) {
  va_list ap; va_start(ap, fmt); NSString *m = [[NSString alloc] initWithFormat:fmt arguments:ap]; va_end(ap);
  NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Logs/VidaasBridge.log"];
  NSString *line = [NSString stringWithFormat:@"%@ [%d] %@\n", [NSDate date], getpid(), m];
  NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:p];
  if (!h) { [line writeToFile:p atomically:NO encoding:NSUTF8StringEncoding error:nil]; return; }
  [h seekToEndOfFile]; [h writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [h closeFile];
}

// ---- DER minimo ----
static int der_tlv(const uint8_t *p, size_t n, size_t *hdr, size_t *len) {
  if (n < 2) return -1; size_t l = p[1], h = 2;
  if (l & 0x80) { int k = l & 0x7f; if (k < 1 || k > 4 || n < 2 + (size_t)k) return -1; l = 0;
    for (int i = 0; i < k; i++) l = (l << 8) | p[2 + i]; h = 2 + k; }
  if (h + l > n) return -1; *hdr = h; *len = l; return 0;
}
static void parse_cert(VBCert *c, NSData *der) {
  const uint8_t *p = der.bytes; size_t n = der.length, h, l;
  if (der_tlv(p, n, &h, &l)) return; p += h; n = l;              // Certificate
  if (der_tlv(p, n, &h, &l)) return; p += h; n = l;              // TBSCertificate
  if (p[0] == 0xA0) { der_tlv(p, n, &h, &l); p += h + l; n -= h + l; } // version
  der_tlv(p, n, &h, &l); c.serial = [NSData dataWithBytes:p length:h + l]; p += h + l; n -= h + l;
  der_tlv(p, n, &h, &l); p += h + l; n -= h + l;                 // sigAlg
  der_tlv(p, n, &h, &l); c.issuer = [NSData dataWithBytes:p length:h + l]; p += h + l; n -= h + l;
  der_tlv(p, n, &h, &l); p += h + l; n -= h + l;                 // validity
  der_tlv(p, n, &h, &l); c.subject = [NSData dataWithBytes:p length:h + l];
}
static NSData *int_bytes(const uint8_t *p, size_t l) { while (l > 1 && p[0] == 0) { p++; l--; } return [NSData dataWithBytes:p length:l]; }
static void parse_pub(VBCert *c, NSData *rsapub) { // RSAPublicKey ::= SEQ { modulus, exponent }
  const uint8_t *p = rsapub.bytes; size_t n = rsapub.length, h, l;
  if (der_tlv(p, n, &h, &l)) return; p += h; n = l;
  der_tlv(p, n, &h, &l); c.mod = int_bytes(p + h, l); p += h + l; n -= h + l;
  der_tlv(p, n, &h, &l); c.exp = int_bytes(p + h, l);
}

// ---- acesso ao VIDaaS pelo macOS ----
// todas as identidades (certificado + chave) publicadas pela extensao do VIDaaS Connect
static NSArray *vidaas_identities(void) {
  NSDictionary *q = @{ (id)kSecClass: (id)kSecClassIdentity, (id)kSecMatchLimit: (id)kSecMatchLimitAll,
    (id)kSecReturnRef: @YES, (id)kSecReturnAttributes: @YES, (id)kSecAttrAccessGroup: (id)kSecAttrAccessGroupToken };
  CFTypeRef out = NULL;
  if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &out) != errSecSuccess || !out) return @[];
  NSMutableArray *r = [NSMutableArray array];
  for (NSDictionary *a in (NSArray *)CFBridgingRelease(out)) {
    NSString *tok = a[(id)kSecAttrTokenID];
    if ([tok hasPrefix:TOKEN_PREFIX]) [r addObject:a[(id)kSecValueRef]];
  }
  return r;
}
static NSData *cert_der(id identity) {
  SecCertificateRef c = NULL; SecIdentityCopyCertificate((__bridge SecIdentityRef)identity, &c);
  return c ? CFBridgingRelease(SecCertificateCopyData(c)) : nil;
}
static void restart_vidaas(void) {
  logf_(@"reiniciando VIDaaS Connect");
  system("/usr/bin/pkill -x VidaaS; /usr/bin/pkill -f vidaasConnectToken; sleep 2; /usr/bin/open -g -a VidaaS");
  for (int i = 0; i < 25; i++) { sleep(2); if (vidaas_identities().count) { logf_(@"VIDaaS voltou"); return; } }
  logf_(@"VIDaaS nao voltou");
}
static int load_identities(int allowRestart) {
  NSArray *ids = vidaas_identities();
  if (!ids.count && allowRestart) { restart_vidaas(); ids = vidaas_identities(); }
  NSMutableArray *list = [NSMutableArray array];
  for (id idr in ids) {
    if (list.count >= MAXC) break;
    SecCertificateRef c = NULL; SecIdentityCopyCertificate((__bridge SecIdentityRef)idr, &c);
    if (!c) continue;
    VBCert *v = [VBCert new];
    v.cert = CFBridgingRelease(SecCertificateCopyData(c));
    v.label = [(NSString *)CFBridgingRelease(SecCertificateCopySubjectSummary(c)) dataUsingEncoding:NSUTF8StringEncoding];
    SecKeyRef pub = SecCertificateCopyKey(c); CFRelease(c);
    if (pub) { NSData *ext = CFBridgingRelease(SecKeyCopyExternalRepresentation(pub, NULL)); CFRelease(pub); if (ext) parse_pub(v, ext); }
    if (!v.mod) continue; // apenas RSA
    parse_cert(v, v.cert);
    uint8_t d[CC_SHA1_DIGEST_LENGTH]; CC_SHA1(v.mod.bytes, (CC_LONG)v.mod.length, d);
    v.ident = [NSData dataWithBytes:d length:sizeof d];
    [list addObject:v];
  }
  g_certs = list;
  logf_(@"%lu certificado(s) VIDaaS carregado(s)", (unsigned long)list.count);
  return (int)list.count;
}
// chave privada atual do certificado idx (a extensao pode ter sido reiniciada)
static SecKeyRef key_for(int idx) {
  if (idx < 0 || idx >= (int)g_certs.count) return NULL;
  NSData *want = g_certs[idx].cert;
  for (id idr in vidaas_identities())
    if ([cert_der(idr) isEqualToData:want]) { SecKeyRef k = NULL; SecIdentityCopyPrivateKey((__bridge SecIdentityRef)idr, &k); return k; }
  return NULL;
}

// assina um resumo usando o algoritmo que a extensao do VIDaaS aceita
static NSData *sign_digest(int idx, int halg, NSData *digest, CK_RV *rv) {
  SecKeyAlgorithm alg;
  switch (halg) {
    case 5: alg = kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw; break; // MD5: resumo puro de 16 bytes
    case 1: alg = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1; break;
    case 256: alg = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256; break;
    case 384: alg = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384; break;
    case 512: alg = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512; break;
    default: *rv = CKR_MECHANISM_INVALID; return nil;
  }
  for (int attempt = 0; attempt < 3; attempt++) {
    SecKeyRef key = key_for(idx);
    if (!key) { restart_vidaas(); continue; }
    CFErrorRef err = NULL; NSDate *t0 = [NSDate date];
    NSData *sig = CFBridgingRelease(SecKeyCreateSignature(key, alg, (__bridge CFDataRef)digest, &err));
    CFRelease(key);
    if (sig) { logf_(@"assinatura ok alg=%d em %.1fs", halg, -[t0 timeIntervalSinceNow]); *rv = CKR_OK; return sig; }
    NSError *e = CFBridgingRelease(err);
    logf_(@"falha na assinatura alg=%d tentativa=%d: %@", halg, attempt + 1, e);
    if ([e.domain isEqualToString:@"CryptoTokenKit"] && e.code == -4 && attempt > 0) { *rv = CKR_FUNCTION_CANCELED; return nil; }
    restart_vidaas(); // a extensao costuma travar na janela de aprovacao; reinicia e tenta de novo
  }
  *rv = CKR_DEVICE_ERROR; return nil;
}

static const uint8_t DI_MD5[] = {0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x04,0x10};
static const uint8_t DI_SHA1[] = {0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14};
static const uint8_t DI_SHA256[] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
static const uint8_t DI_SHA384[] = {0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30};
static const uint8_t DI_SHA512[] = {0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40};

// CKM_RSA_PKCS recebe DigestInfo pronto: identifica o hash e extrai o resumo
static NSData *sign_digestinfo(int idx, NSData *in, CK_RV *rv) {
  struct { const uint8_t *p; size_t n; int alg; size_t dl; } t[] = {
    {DI_MD5, sizeof DI_MD5, 5, 16}, {DI_SHA1, sizeof DI_SHA1, 1, 20}, {DI_SHA256, sizeof DI_SHA256, 256, 32},
    {DI_SHA384, sizeof DI_SHA384, 384, 48}, {DI_SHA512, sizeof DI_SHA512, 512, 64}};
  for (int i = 0; i < 5; i++)
    if (in.length == t[i].n + t[i].dl && !memcmp(in.bytes, t[i].p, t[i].n))
      return sign_digest(idx, t[i].alg, [in subdataWithRange:NSMakeRange(t[i].n, t[i].dl)], rv);
  // DigestInfo MD5 sem o NULL de parametros
  static const uint8_t DI_MD5_NONULL[] = {0x30,0x1e,0x30,0x0a,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x04,0x10};
  if (in.length == sizeof DI_MD5_NONULL + 16 && !memcmp(in.bytes, DI_MD5_NONULL, sizeof DI_MD5_NONULL))
    return sign_digest(idx, 5, [in subdataWithRange:NSMakeRange(sizeof DI_MD5_NONULL, 16)], rv);
  logf_(@"CKM_RSA_PKCS com dado nao reconhecido (%lu bytes)", (unsigned long)in.length);
  *rv = CKR_DATA_INVALID; return nil;
}

// ---- atributos ----
static NSData *bb(CK_BBOOL v) { return [NSData dataWithBytes:&v length:1]; }
static NSData *ul(CK_ULONG v) { return [NSData dataWithBytes:&v length:sizeof v]; }
static int obj_valid(CK_OBJECT_HANDLE o) { return o >= 1 && o <= 2 * g_certs.count; }
static NSData *attr_of(CK_OBJECT_HANDLE o, CK_ATTRIBUTE_TYPE t) {
  if (!obj_valid(o)) return nil;
  VBCert *c = g_certs[(o - 1) / 2];
  if (o % 2 == 1) switch (t) { // certificado
    case 0x0: return ul(CKO_CERTIFICATE); case 0x1: return bb(1); case 0x2: return bb(0);
    case 0x3: return c.label; case 0x11: return c.cert; case 0x80: return ul(0);
    case 0x81: return c.issuer; case 0x82: return c.serial; case 0x86: return bb(0);
    case 0x87: return ul(0); case 0x101: return c.subject; case 0x102: return c.ident;
    case 0x170: return bb(0);
  }
  else switch (t) { // chave privada
    case 0x0: return ul(CKO_PRIVATE_KEY); case 0x1: return bb(1); case 0x2: return bb(1);
    case 0x3: return c.label; case 0x100: return ul(0); case 0x101: return c.subject; case 0x102: return c.ident;
    case 0x103: return bb(1); case 0x104: return bb(0); case 0x105: return bb(0); case 0x106: return bb(0);
    case 0x107: return bb(0); case 0x108: return bb(1); case 0x109: return bb(0); case 0x10C: return bb(0);
    case 0x120: return c.mod; case 0x121: return ul(c.mod.length * 8); case 0x122: return c.exp;
    case 0x162: return bb(0); case 0x163: return bb(1); case 0x164: return bb(1); case 0x165: return bb(1);
    case 0x170: return bb(0); case 0x202: return bb(0);
  }
  return nil;
}

// ---- funcoes PKCS#11 ----
static void pad(CK_UTF8CHAR *d, size_t n, const char *s) { memset(d, ' ', n); size_t l = strlen(s); memcpy(d, s, l < n ? l : n); }
static Sess *sess(CK_SESSION_HANDLE h) { return (h >= 1 && h <= MAXS && g_s[h].open) ? &g_s[h] : NULL; }

CK_RV C_GetFunctionList(CK_FUNCTION_LIST **pp);
static CK_RV C_Initialize(void *a) { pthread_mutex_lock(&g_mx);
  if (g_init) { pthread_mutex_unlock(&g_mx); return CKR_CRYPTOKI_ALREADY_INITIALIZED; }
  g_init = 1; memset(g_s, 0, sizeof g_s); @autoreleasepool { logf_(@"C_Initialize"); load_identities(1); }
  pthread_mutex_unlock(&g_mx); return CKR_OK; }
static CK_RV C_Finalize(void *a) { g_init = 0; return CKR_OK; }
static CK_RV C_GetInfo(CK_INFO *i) { if (!i) return CKR_ARGUMENTS_BAD; memset(i, 0, sizeof *i);
  i->cryptokiVersion = (CK_VERSION){2, 20}; pad(i->manufacturerID, 32, "VidaasBridge");
  pad(i->libraryDescription, 32, "Ponte VIDaaS para macOS"); i->libraryVersion = (CK_VERSION){1, 0}; return CKR_OK; }
static CK_RV C_GetSlotList(CK_BBOOL tp, CK_SLOT_ID *l, CK_ULONG *n) { if (!n) return CKR_ARGUMENTS_BAD;
  if (!l) { *n = 1; return CKR_OK; } if (*n < 1) { *n = 1; return CKR_BUFFER_TOO_SMALL; } l[0] = SLOT; *n = 1; return CKR_OK; }
static CK_RV C_GetSlotInfo(CK_SLOT_ID s, CK_SLOT_INFO *i) { if (s != SLOT) return CKR_SLOT_ID_INVALID; memset(i, 0, sizeof *i);
  pad(i->slotDescription, 64, "VIDaaS (nuvem) via macOS"); pad(i->manufacturerID, 32, "VidaasBridge");
  i->flags = 0x1 | 0x4; /* TOKEN_PRESENT | HW_SLOT */ return CKR_OK; }
static CK_RV C_GetTokenInfo(CK_SLOT_ID s, CK_TOKEN_INFO *i) { if (s != SLOT) return CKR_SLOT_ID_INVALID; memset(i, 0, sizeof *i);
  pad(i->label, 32, "VIDaaS"); pad(i->manufacturerID, 32, "Valid / VidaasBridge"); pad(i->model, 16, "Nuvem");
  pad(i->serialNumber, 16, "VIDAAS0001");
  i->flags = 0x400 /*TOKEN_INITIALIZED*/ | 0x8 /*USER_PIN_INITIALIZED*/ | 0x100 /*PROTECTED_AUTH_PATH*/ | 0x2 /*WRITE_PROTECTED*/;
  i->ulMaxSessionCount = MAXS; i->ulMaxRwSessionCount = MAXS; i->ulMaxPinLen = 64; i->ulMinPinLen = 0;
  i->ulTotalPublicMemory = i->ulFreePublicMemory = i->ulTotalPrivateMemory = i->ulFreePrivateMemory = CK_UNAVAILABLE;
  i->hardwareVersion = i->firmwareVersion = (CK_VERSION){1, 0}; return CKR_OK; }
static const CK_MECHANISM_TYPE MECHS[] = {CKM_RSA_PKCS, CKM_MD5_RSA_PKCS, CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS};
static CK_RV C_GetMechanismList(CK_SLOT_ID s, CK_MECHANISM_TYPE *l, CK_ULONG *n) { size_t c = sizeof MECHS / sizeof *MECHS;
  if (!l) { *n = c; return CKR_OK; } if (*n < c) { *n = c; return CKR_BUFFER_TOO_SMALL; } memcpy(l, MECHS, sizeof MECHS); *n = c; return CKR_OK; }
static CK_RV C_GetMechanismInfo(CK_SLOT_ID s, CK_MECHANISM_TYPE m, CK_MECHANISM_INFO *i) {
  for (size_t k = 0; k < sizeof MECHS / sizeof *MECHS; k++) if (MECHS[k] == m) { i->ulMinKeySize = 1024; i->ulMaxKeySize = 4096; i->flags = 0x1 | 0x800; return CKR_OK; }
  return CKR_MECHANISM_INVALID; }
static CK_RV C_OpenSession(CK_SLOT_ID s, CK_FLAGS f, void *app, void *notify, CK_SESSION_HANDLE *h) {
  if (s != SLOT) return CKR_SLOT_ID_INVALID; pthread_mutex_lock(&g_mx);
  for (int k = 1; k <= MAXS; k++) if (!g_s[k].open) { memset(&g_s[k], 0, sizeof g_s[k]); g_s[k].open = 1; *h = k; pthread_mutex_unlock(&g_mx); return CKR_OK; }
  pthread_mutex_unlock(&g_mx); return CKR_GENERAL_ERROR; }
static CK_RV C_CloseSession(CK_SESSION_HANDLE h) { Sess *s = sess(h); if (!s) return CKR_SESSION_HANDLE_INVALID; if (s->buf) CFRelease(s->buf); s->buf = NULL; s->open = 0; return CKR_OK; }
static CK_RV C_CloseAllSessions(CK_SLOT_ID sl) { for (int k = 1; k <= MAXS; k++) { if (g_s[k].buf) CFRelease(g_s[k].buf); g_s[k].buf = NULL; g_s[k].open = 0; } return CKR_OK; }
static CK_RV C_GetSessionInfo(CK_SESSION_HANDLE h, CK_SESSION_INFO *i) { if (!sess(h)) return CKR_SESSION_HANDLE_INVALID;
  i->slotID = SLOT; i->state = 3 /*RW_USER_FUNCTIONS*/; i->flags = 0x4 | 0x2; i->ulDeviceError = 0; return CKR_OK; }
static CK_RV C_Login(CK_SESSION_HANDLE h, CK_USER_TYPE u, CK_UTF8CHAR *pin, CK_ULONG n) { return sess(h) ? CKR_OK : CKR_SESSION_HANDLE_INVALID; }
static CK_RV C_Logout(CK_SESSION_HANDLE h) { return CKR_OK; }
static CK_RV C_GetAttributeValue(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, CK_ATTRIBUTE *t, CK_ULONG n) {
  if (!sess(h)) return CKR_SESSION_HANDLE_INVALID; if (!obj_valid(o)) return CKR_OBJECT_HANDLE_INVALID;
  CK_RV rv = CKR_OK;
  for (CK_ULONG k = 0; k < n; k++) { NSData *v = attr_of(o, t[k].type);
    if (!v) { t[k].ulValueLen = CK_UNAVAILABLE; rv = CKR_ATTRIBUTE_TYPE_INVALID; continue; }
    if (!t[k].pValue) { t[k].ulValueLen = v.length; continue; }
    if (t[k].ulValueLen < v.length) { t[k].ulValueLen = CK_UNAVAILABLE; rv = CKR_BUFFER_TOO_SMALL; continue; }
    memcpy(t[k].pValue, v.bytes, v.length); t[k].ulValueLen = v.length; }
  return rv; }
static int matches(CK_OBJECT_HANDLE o, CK_ATTRIBUTE *t, CK_ULONG n) {
  for (CK_ULONG k = 0; k < n; k++) { NSData *v = attr_of(o, t[k].type);
    if (!v || v.length != t[k].ulValueLen || (t[k].ulValueLen && memcmp(v.bytes, t[k].pValue, v.length))) return 0; }
  return 1; }
static CK_RV C_FindObjectsInit(CK_SESSION_HANDLE h, CK_ATTRIBUTE *t, CK_ULONG n) { Sess *s = sess(h);
  if (!s) return CKR_SESSION_HANDLE_INVALID; if (s->findActive) return CKR_OPERATION_ACTIVE;
  @autoreleasepool { if (!g_certs.count) load_identities(1); }
  s->findActive = 1; s->findIdx = 0; s->findN = 0;
  for (CK_OBJECT_HANDLE o = 1; o <= 2 * g_certs.count; o++) if (matches(o, t, n)) s->found[s->findN++] = o;
  return CKR_OK; }
static CK_RV C_FindObjects(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE *o, CK_ULONG max, CK_ULONG *cnt) { Sess *s = sess(h);
  if (!s) return CKR_SESSION_HANDLE_INVALID; if (!s->findActive) return CKR_OPERATION_NOT_INITIALIZED;
  *cnt = 0; while (s->findIdx < s->findN && *cnt < max) o[(*cnt)++] = s->found[s->findIdx++]; return CKR_OK; }
static CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE h) { Sess *s = sess(h); if (!s) return CKR_SESSION_HANDLE_INVALID; s->findActive = 0; return CKR_OK; }
static CK_RV C_SignInit(CK_SESSION_HANDLE h, CK_MECHANISM *m, CK_OBJECT_HANDLE k) { Sess *s = sess(h);
  if (!s) return CKR_SESSION_HANDLE_INVALID; if (!obj_valid(k) || k % 2) return CKR_KEY_HANDLE_INVALID; s->certIdx = (int)(k - 1) / 2;
  int ok = 0; for (size_t i = 0; i < sizeof MECHS / sizeof *MECHS; i++) if (MECHS[i] == m->mechanism) ok = 1;
  if (!ok) return CKR_MECHANISM_INVALID;
  s->signActive = 1; s->mech = m->mechanism; if (s->buf) CFRelease(s->buf); s->buf = CFDataCreateMutable(NULL, 0);
  CC_MD5_Init(&s->m5); CC_SHA1_Init(&s->s1); CC_SHA256_Init(&s->s256);
  if (m->mechanism == CKM_SHA384_RSA_PKCS) CC_SHA384_Init(&s->s512); else CC_SHA512_Init(&s->s512);
  return CKR_OK; }
static CK_RV sign_update(Sess *s, const void *d, CK_ULONG n) {
  switch (s->mech) {
    case CKM_RSA_PKCS: CFDataAppendBytes(s->buf, d, (CFIndex)n); break;
    case CKM_MD5_RSA_PKCS: CC_MD5_Update(&s->m5, d, (CC_LONG)n); break;
    case CKM_SHA1_RSA_PKCS: CC_SHA1_Update(&s->s1, d, (CC_LONG)n); break;
    case CKM_SHA256_RSA_PKCS: CC_SHA256_Update(&s->s256, d, (CC_LONG)n); break;
    case CKM_SHA384_RSA_PKCS: CC_SHA384_Update(&s->s512, d, (CC_LONG)n); break;
    case CKM_SHA512_RSA_PKCS: CC_SHA512_Update(&s->s512, d, (CC_LONG)n); break; }
  return CKR_OK; }
static CK_RV sign_final(Sess *s, CK_BYTE *out, CK_ULONG *outLen) {
  NSData *mod = s->certIdx < (int)g_certs.count ? g_certs[s->certIdx].mod : nil; CK_ULONG need = mod.length ? mod.length : 256;
  if (!out) { *outLen = need; return CKR_OK; }                 // so consulta o tamanho
  if (*outLen < need) { *outLen = need; return CKR_BUFFER_TOO_SMALL; }
  CK_RV rv = CKR_OK; NSData *sig = nil; uint8_t d[64];
  @autoreleasepool {
    switch (s->mech) {
      case CKM_RSA_PKCS: sig = sign_digestinfo(s->certIdx, (__bridge NSData *)s->buf, &rv); break;
      case CKM_MD5_RSA_PKCS: CC_MD5_Final(d, &s->m5); sig = sign_digest(s->certIdx, 5, [NSData dataWithBytes:d length:16], &rv); break;
      case CKM_SHA1_RSA_PKCS: CC_SHA1_Final(d, &s->s1); sig = sign_digest(s->certIdx, 1, [NSData dataWithBytes:d length:20], &rv); break;
      case CKM_SHA256_RSA_PKCS: CC_SHA256_Final(d, &s->s256); sig = sign_digest(s->certIdx, 256, [NSData dataWithBytes:d length:32], &rv); break;
      case CKM_SHA384_RSA_PKCS: CC_SHA384_Final(d, &s->s512); sig = sign_digest(s->certIdx, 384, [NSData dataWithBytes:d length:48], &rv); break;
      case CKM_SHA512_RSA_PKCS: CC_SHA512_Final(d, &s->s512); sig = sign_digest(s->certIdx, 512, [NSData dataWithBytes:d length:64], &rv); break; }
    if (sig) { memcpy(out, sig.bytes, sig.length); *outLen = sig.length; }
  }
  s->signActive = 0; if (s->buf) CFRelease(s->buf); s->buf = NULL; return rv; }
static CK_RV C_Sign(CK_SESSION_HANDLE h, CK_BYTE *d, CK_ULONG n, CK_BYTE *out, CK_ULONG *outLen) { Sess *s = sess(h);
  if (!s) return CKR_SESSION_HANDLE_INVALID; if (!s->signActive) return CKR_OPERATION_NOT_INITIALIZED;
  if (!out) { NSData *mod = s->certIdx < (int)g_certs.count ? g_certs[s->certIdx].mod : nil; *outLen = mod.length ? mod.length : 256; return CKR_OK; }
  sign_update(s, d, n); return sign_final(s, out, outLen); }
static CK_RV C_SignUpdate(CK_SESSION_HANDLE h, CK_BYTE *d, CK_ULONG n) { Sess *s = sess(h);
  if (!s) return CKR_SESSION_HANDLE_INVALID; if (!s->signActive) return CKR_OPERATION_NOT_INITIALIZED; return sign_update(s, d, n); }
static CK_RV C_SignFinal(CK_SESSION_HANDLE h, CK_BYTE *out, CK_ULONG *outLen) { Sess *s = sess(h);
  if (!s) return CKR_SESSION_HANDLE_INVALID; if (!s->signActive) return CKR_OPERATION_NOT_INITIALIZED; return sign_final(s, out, outLen); }
static CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE h) { return 0x51; /* FUNCTION_NOT_PARALLEL */ }
static CK_RV notsup(void) { return CKR_FUNCTION_NOT_SUPPORTED; }

static CK_FUNCTION_LIST g_fl;
CK_RV C_GetFunctionList(CK_FUNCTION_LIST **pp) {
  if (!pp) return CKR_ARGUMENTS_BAD;
  g_fl.version = (CK_VERSION){2, 20};
  for (int i = 0; i < 68; i++) g_fl.f[i] = (CK_FN)notsup;
#define SET(i, fn) g_fl.f[i] = (CK_FN)fn
  SET(0, C_Initialize); SET(1, C_Finalize); SET(2, C_GetInfo); SET(3, C_GetFunctionList); SET(4, C_GetSlotList);
  SET(5, C_GetSlotInfo); SET(6, C_GetTokenInfo); SET(7, C_GetMechanismList); SET(8, C_GetMechanismInfo);
  SET(12, C_OpenSession); SET(13, C_CloseSession); SET(14, C_CloseAllSessions); SET(15, C_GetSessionInfo);
  SET(18, C_Login); SET(19, C_Logout); SET(24, C_GetAttributeValue); SET(26, C_FindObjectsInit);
  SET(27, C_FindObjects); SET(28, C_FindObjectsFinal); SET(42, C_SignInit); SET(43, C_Sign);
  SET(44, C_SignUpdate); SET(45, C_SignFinal); SET(65, C_GetFunctionStatus);
  *pp = &g_fl; return CKR_OK;
}
