#include "des.h"
#include <iostream>
#include <fstream>
#include <bitset>
#include <cstring>
using namespace std;

DES::DES() {}
DES::~DES() {}

void DES::IP_Transform(char data[64]) {
  char temp[64];
  for(int i = 0; i < 64; i++) {
    temp[i] = data[IP_Table[i]];
  }
  memcpy(data,temp,64);
}

void DES::GenerateSubKey(char key[64], char subKeys[16][48]) {
  char temp[56];
  PC1_Transform(key,temp);
  for(int i = 0; i < 16; i++) {
    Shift_Left(temp, MOVE_TIMES[i]);
    PC2_Transform(temp, subKeys[i]);
  }
}

void DES::PC1_Transform(char key[64], char tempbts[56]) {
  for(int i = 0; i < 56; i++) {
    tempbts[i] = key[PC_1[i]];
  }
}

void DES::PC2_Transform(char key[56], char tempbts[48]) {
  for(int i = 0; i < 48; i++) {
    tempbts[i] = key[PC_2[i]];
  }
}

void DES::Shift_Left(char data[56], int time){    
  char temp[56];
  memcpy(temp,data,time);
  memcpy(temp+time,data+28,time);
  memcpy(data,data+time,28-time);
  memcpy(data+28-time,temp,time);

  memcpy(data+28,data+28+time,28-time);
  memcpy(data+56-time,temp+time,time);    

}

void DES::IP_1_Transform(char data[64]) {
  char temp[64];
  for(int i = 0; i < 64; i++) {
    temp[i] = data[IP_1_Table[i]];
  }
  memcpy(data,temp,64);
}

void DES::E_Transform(char data[48]) {
  char temp[48];
  for(int i = 0; i < 48; i++) {
    temp[i] = data[E_Table[i]];
  }
  memcpy(data,temp,48);
}

void DES::P_Transform(char data[32]) {
  char temp[32];
  for(int i = 0; i < 32; i++) {
    temp[i] = data[P_Table[i]];
  }
  memcpy(data,temp,32);
}

void DES::XOR(char R[48], char L[48] ,int count) {
  for(int i = 0; i < count; i++) {
    R[i] ^= L[i];
  }
}

void DES::SBOX(char data[48]) {
  int line,row,output;
  int cur1,cur2;
  for(int i = 0; i < 8; i++){
    cur1 = i * 6;
    cur2 = i<< 2;

    line = (data[cur1]<<1) + data[cur1+5];
    row = (data[cur1+1]<<3) + (data[cur1+2]<<2)
        + (data[cur1+3]<<1) + data[cur1+4];
    output = S[i][line][row];

    data[cur2] = (output&0X08)>>3;
    data[cur2+1] = (output&0X04)>>2;
    data[cur2+2] = (output&0X02)>>1;
    data[cur2+3] = output&0x01;
  }
}

void DES::Swap(char left[32], char right[32]) {
  char temp[32];
  memcpy(temp,left,32);    
  memcpy(left,right,32);    
  memcpy(right,temp,32);
}

void DES::CharToBit(char ch[8],char bit[64]){
  for(int i = 0; i < 8; i++) {
    for (int j = 0; j < 8; j++) {
      *(bit + i * 8 + j) = (ch[i]>> j) & 1;
    }
  }
}

void DES::BitToChar(char bit[64],char ch[8]){
  memset(ch, 0, 8);
  for(int i = 0; i < 8; i++) {
    for (int j = 0; j < 8; j++) {
      *(ch + i) |= bit[i * 8 + j]<< j;
    }
  }
}

void DES::Encrypt64Bit(char plainBlock[8], char subKeys[16][48], char cipherBlock[8]){
  char plainBits[64];
  char copyRight[48];
  int i;

  CharToBit(plainBlock,plainBits);        
  IP_Transform(plainBits);

  for(i = 0; i < 16; i++){        
    memcpy(copyRight,plainBits+32,32);
    E_Transform(copyRight);
    XOR(copyRight,subKeys[i],48);    
    SBOX(copyRight);
    P_Transform(copyRight);
    XOR(plainBits,copyRight,32);
    if(i != 15){
      Swap(plainBits,plainBits+32);
    }
  }
  IP_1_Transform(plainBits);
  BitToChar(plainBits,cipherBlock);
}

void DES::Decrypt64Bit(char cipherBlock[8], char subKeys[16][48],char plainBlock[8]){
  char cipherBits[64];
  char copyRight[48];

  CharToBit(cipherBlock,cipherBits);        
  IP_Transform(cipherBits);

  for(int i = 15; i >= 0; i--){        
    memcpy(copyRight,cipherBits+32,32);
    E_Transform(copyRight);
    XOR(copyRight,subKeys[i],48);        
    SBOX(copyRight);
    P_Transform(copyRight);        
    XOR(cipherBits,copyRight,32);
    if(i != 0) {
      Swap(cipherBits,cipherBits+32);
    }
  }
  IP_1_Transform(cipherBits);
  BitToChar(cipherBits,plainBlock);
}

void DES::Encrypt(char *plainFile, char *keyStr,char *cipherFile){
  FILE *plain,*cipher;
  int count;
  char plainBlock[8],cipherBlock[8],keyBlock[8];
  char bKey[64];
  char subKeys[16][48];
  if((plain = fopen(plainFile,"rb")) == NULL){
    cout<< "read error"<<endl;
    return;
  }    
  if((cipher = fopen(cipherFile,"wb")) == NULL){
    cout<< "write error"<< endl;
    return;
  }
  memcpy(keyBlock,keyStr,8);
  CharToBit(keyBlock,bKey);
  GenerateSubKey(bKey,subKeys);

  while(!feof(plain)){
    if((count = fread(plainBlock, sizeof(char), 8, plain)) == 8){
      Encrypt64Bit(plainBlock, subKeys, cipherBlock);
      fwrite(cipherBlock, sizeof(char), 8, cipher);    
    }
  }
  if(count){
    memset(plainBlock + count,'\0', 7 - count);
    plainBlock[7] = 8 - count;
    Encrypt64Bit(plainBlock,subKeys,cipherBlock);
    fwrite(cipherBlock, sizeof(char), 8, cipher);
  }
  fclose(plain);
  fclose(cipher);
}

void DES::Decrypt(char *cipherFile, char *keyStr,char *plainFile){
  FILE *plain, *cipher;
  int count,times = 0;
  long fileLen;
  char plainBlock[8], cipherBlock[8], keyBlock[8];
  char bKey[64];
  char subKeys[16][48];
  if((cipher = fopen(cipherFile,"rb")) == NULL){
    cout<< "read error"<< endl;
    return;
  }
  if((plain = fopen(plainFile,"wb")) == NULL){
    cout<< "write error"<< endl;
    return;
  }
  memcpy(keyBlock,keyStr,8);
  CharToBit(keyBlock,bKey);
  GenerateSubKey(bKey,subKeys); 
  fseek(cipher, 0, SEEK_END);    //将文件指针置尾
  fileLen = ftell(cipher);    //取文件指针当前位置
  rewind(cipher);                //将文件指针重指向文件头
  while(1){
    fread(cipherBlock,sizeof(char), 8, cipher);
    Decrypt64Bit(cipherBlock, subKeys, plainBlock);                        
    times += 8;
    if(times < fileLen){
      fwrite(plainBlock, sizeof(char), 8, plain);
    } else {
      break;
    }
  }
  if(plainBlock[7] < 8) {
    for(count = 8 - plainBlock[7]; count < 7; count++){
      if(plainBlock[count] != '\0'){
        break;
      }
    }
  }    
  if(count == 7) {
    fwrite(plainBlock, sizeof(char), 8 - plainBlock[7], plain);
  } else {
    fwrite(plainBlock, sizeof(char), 8, plain);
  }
  fclose(plain);
  fclose(cipher);
}

int main() {
  DES d;
  d.Encrypt("plain.txt","key.txt","cipher.txt");
  d.Decrypt("cipher.txt","key.txt","newplain.txt");  
  return 0;  
}