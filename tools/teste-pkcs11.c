#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include "p11min.h"
#define CALL(i, ...) ((CK_RV(*)())fl->f[i])(__VA_ARGS__)
int main(int argc,char**argv){ setvbuf(stdout,0,_IONBF,0);
 void*h=dlopen(getenv("P11LIB"),RTLD_NOW); if(!h){printf("dlopen %s\n",dlerror());return 1;}
 CK_RV(*gfl)(CK_FUNCTION_LIST**)=dlsym(h,"C_GetFunctionList"); CK_FUNCTION_LIST*fl; gfl(&fl);
 printf("ver %d.%d\n",fl->version.major,fl->version.minor);
 printf("init %lx\n",CALL(I_Initialize,NULL));
 CK_SLOT_ID slots[16]; CK_ULONG n=16; printf("slots %lx n=%lu\n",CALL(I_GetSlotList,1,slots,&n),n);
 if(!n) return 0;
 CK_SLOT_ID s=slots[0]; CK_TOKEN_INFO ti; memset(&ti,0,sizeof ti);
 printf("tokinfo %lx label=%.32s model=%.16s flags=%lx\n",CALL(I_GetTokenInfo,s,&ti),ti.label,ti.model,ti.flags);
 CK_MECHANISM_TYPE m[64]; CK_ULONG mn=64; CALL(I_GetMechanismList,s,m,&mn);
 printf("mechs:"); for(CK_ULONG i=0;i<mn;i++) printf(" %lx",m[i]); printf("\n");
 CK_SESSION_HANDLE se; printf("open %lx\n",CALL(I_OpenSession,s,6,NULL,NULL,&se));
 for(CK_OBJECT_CLASS cls=1; cls<=3; cls+=2){ /* 1=cert 3=privkey */
  CK_ATTRIBUTE t={0,&cls,sizeof cls};
  printf("findinit cls=%lu %lx\n",cls,CALL(I_FindObjectsInit,se,&t,1));
  CK_OBJECT_HANDLE o[8]; CK_ULONG on=0; CALL(I_FindObjects,se,o,8,&on); CALL(I_FindObjectsFinal,se);
  printf(" found %lu\n",on);
  for(CK_ULONG k=0;k<on;k++){ CK_BYTE id[64]; CK_ATTRIBUTE a={0x102,id,64}; CK_RV r=CALL(I_GetAttributeValue,se,o[k],&a,1);
   printf("  obj %lu id rv=%lx len=%lu\n",o[k],r,a.ulValueLen);
   if(cls==3 && argc>1){ CK_ULONG mech=strtoul(argv[1],0,16); CK_MECHANISM M={mech,0,0};
     unsigned char data[64]; int dl;
     if(mech==1){ /* RSA_PKCS with MD5 DigestInfo */ unsigned char p[]={0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x04,0x10}; memcpy(data,p,18); memset(data+18,7,16); dl=34; }
     else { memcpy(data,"teste-ponte-vidaas",18); dl=18; }
     printf("  signinit mech=%lx %lx\n",mech,CALL(I_SignInit,se,&M,o[k]));
     unsigned char sig[512]; CK_ULONG sl=512; CK_RV rr=CALL(I_Sign,se,data,(CK_ULONG)dl,sig,&sl);
     printf("  sign rv=%lx len=%lu\n",rr,sl);
     if(!rr){FILE*f=fopen("sig.bin","wb");fwrite(sig,1,sl,f);fclose(f);}
   }
  }
 }
 fflush(stdout); _exit(0); /* nao chama CloseSession (bug de double free) */
}
