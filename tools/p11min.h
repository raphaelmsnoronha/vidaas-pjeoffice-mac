#include <stdint.h>
typedef unsigned long CK_ULONG, CK_RV, CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_FLAGS, CK_MECHANISM_TYPE, CK_ATTRIBUTE_TYPE, CK_OBJECT_CLASS;
typedef unsigned char CK_BYTE, CK_BBOOL;
#pragma pack(push,1)
#pragma pack(pop)
typedef struct { CK_ATTRIBUTE_TYPE type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_MECHANISM_TYPE mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_BYTE major, minor; } CK_VERSION;
typedef struct { CK_BYTE label[32], manufacturerID[32], model[16], serialNumber[16]; CK_FLAGS flags;
 CK_ULONG a,b,c,d,e,f,g,h,i,j; CK_VERSION hw, fw; CK_BYTE utcTime[16]; } CK_TOKEN_INFO;
typedef struct { CK_ULONG ulMinKeySize, ulMaxKeySize; CK_FLAGS flags; } CK_MECHANISM_INFO;
typedef CK_RV (*fn_t)();
typedef struct { CK_VERSION version; fn_t f[68]; } CK_FUNCTION_LIST;
/* indices in function list */
enum { I_Initialize=0, I_Finalize, I_GetInfo, I_GetFunctionList, I_GetSlotList, I_GetSlotInfo, I_GetTokenInfo,
 I_GetMechanismList, I_GetMechanismInfo, I_InitToken, I_InitPIN, I_SetPIN, I_OpenSession, I_CloseSession,
 I_CloseAllSessions, I_GetSessionInfo, I_GetOperationState, I_SetOperationState, I_Login, I_Logout,
 I_CreateObject, I_CopyObject, I_DestroyObject, I_GetObjectSize, I_GetAttributeValue, I_SetAttributeValue,
 I_FindObjectsInit, I_FindObjects, I_FindObjectsFinal, I_EncryptInit, I_Encrypt, I_EncryptUpdate, I_EncryptFinal,
 I_DecryptInit, I_Decrypt, I_DecryptUpdate, I_DecryptFinal, I_DigestInit, I_Digest, I_DigestUpdate, I_DigestKey,
 I_DigestFinal, I_SignInit, I_Sign, I_SignUpdate, I_SignFinal };
