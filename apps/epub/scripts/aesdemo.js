 var plaintext = 'This is a dummy string to be encrypted.';
  
  // Rijndael Reference Implementation
  // Copyright (c) 2001 Fritz Schneider
  // Source: http://javascript.about.com/library/blencrypt.htm
  var BS = 128;
  var BB = 128;
  var RA = [, , , , [, , , , 10, , 12, , 14], , [, , , , 12, , 12, , 14], , [, , , , 14, , 14, , 14]];
  var SO = [, , , , [, 1, 2, 3], , [, 1, 2, 3], , [, 1, 3, 4]];
  var RC = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91];
  var SB = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22];
  var SBI = [82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125];
  
  function cSL(TA, PO) {
   var T = TA.slice(0, PO);
   TA = TA.slice(PO).concat(T);
   return TA;
  }
  var Nk = BS / 32;
  var Nb = BB / 32;
  var Nr = RA[Nk][Nb];
  
  function XT(P) {
   P <<= 1;
   return ((P & 0x100) ? (P ^ 0x11B) : (P));
  }
  
  function GF(x, y) {
   var B, R = 0;
   for (B = 1; B < 256; B *= 2, y = XT(y)) {
    if (x & B) R ^= y;
   }
   return R;
  }
  
  function bS(SE, DR) {
   var S;
   if (DR == "e") S = SB;
   else S = SBI;
   for (var i = 0; i < 4; i++) for (var j = 0; j < Nb; j++) SE[i][j] = S[SE[i][j]];
  }
  
  function sR(SE, DR) {
   for (var i = 1; i < 4; i++) if (DR == "e") SE[i] = cSL(SE[i], SO[Nb][i]);
   else SE[i] = cSL(SE[i], Nb - SO[Nb][i]);
  }
  
  function mC(SE, DR) {
   var b = [];
   for (var j = 0; j < Nb; j++) {
    for (var i = 0; i < 4; i++) {
     if (DR == "e") b[i] = GF(SE[i][j], 2) ^ GF(SE[(i + 1) % 4][j], 3) ^ SE[(i + 2) % 4][j] ^ SE[(i + 3) % 4][j];
     else b[i] = GF(SE[i][j], 0xE) ^ GF(SE[(i + 1) % 4][j], 0xB) ^ GF(SE[(i + 2) % 4][j], 0xD) ^ GF(SE[(i + 3) % 4][j], 9);
    }
    for (var i = 0; i < 4; i++) SE[i][j] = b[i];
   }
  }
  
  function aRK(SE, RK) {
   for (var j = 0; j < Nb; j++) {
    SE[0][j] ^= (RK[j] & 0xFF);
    SE[1][j] ^= ((RK[j] >> 8) & 0xFF);
    SE[2][j] ^= ((RK[j] >> 16) & 0xFF);
    SE[3][j] ^= ((RK[j] >> 24) & 0xFF);
   }
  }
  
  function YE(Y) {
   var EY = [];
   var T;
   Nk = BS / 32;
   Nb = BB / 32;
   Nr = RA[Nk][Nb];
   for (var j = 0; j < Nk; j++) EY[j] = (Y[4 * j]) | (Y[4 * j + 1] << 8) | (Y[4 * j + 2] << 16) | (Y[4 * j + 3] << 24);
   for (j = Nk; j < Nb * (Nr + 1); j++) {
    T = EY[j - 1];
    if (j % Nk == 0) T = ((SB[(T >> 8) & 0xFF]) | (SB[(T >> 16) & 0xFF] << 8) | (SB[(T >> 24) & 0xFF] << 16) | (SB[T & 0xFF] << 24)) ^ RC[Math.floor(j / Nk) - 1];
    else if (Nk > 6 && j % Nk == 4) T = (SB[(T >> 24) & 0xFF] << 24) | (SB[(T >> 16) & 0xFF] << 16) | (SB[(T >> 8) & 0xFF] << 8) | (SB[T & 0xFF]);
    EY[j] = EY[j - Nk] ^ T;
   }
   return EY;
  }
  
  function Rd(SE, RK) {
   bS(SE, "e");
   sR(SE, "e");
   mC(SE, "e");
   aRK(SE, RK);
  }
  
  function iRd(SE, RK) {
   aRK(SE, RK);
   mC(SE, "d");
   sR(SE, "d");
   bS(SE, "d");
  }
  
  function FRd(SE, RK) {
   bS(SE, "e");
   sR(SE, "e");
   aRK(SE, RK);
  }
  
  function iFRd(SE, RK) {
   aRK(SE, RK);
   sR(SE, "d");
   bS(SE, "d");
  }
  
  function encrypt(bk, EY) {
   var i;
   if (!bk || bk.length * 8 != BB) return;
   if (!EY) return;
   bk = pB(bk);
   aRK(bk, EY);
   for (i = 1; i < Nr; i++) Rd(bk, EY.slice(Nb * i, Nb * (i + 1)));
   FRd(bk, EY.slice(Nb * Nr));
   return uPB(bk);
  }
  
  function decrypt(bk, EY) {
   var i;
   if (!bk || bk.length * 8 != BB) return;
   if (!EY) return;
   bk = pB(bk);
   iFRd(bk, EY.slice(Nb * Nr));
   for (i = Nr - 1; i > 0; i--) iRd(bk, EY.slice(Nb * i, Nb * (i + 1)));
   aRK(bk, EY);
   return uPB(bk);
  }
  
  function byteArrayToString(bA) {
   var R = "";
   for (var i = 0; i < bA.length; i++) if (bA[i] != 0) R += String.fromCharCode(bA[i]);
   return R;
  }
  
  function byteArrayToHex(bA) {
   var R = "";
   if (!bA) return;
   for (var i = 0; i < bA.length; i++) R += ((bA[i] < 16) ? "0" : "") + bA[i].toString(16);
   return R;
  }
  
  function hexToByteArray(hS) {
   var bA = [];
   if (hS.length % 2) return;
   if (hS.indexOf("0x") == 0 || hS.indexOf("0X") == 0) hS = hS.substring(2);
   for (var i = 0; i < hS.length; i += 2) bA[Math.floor(i / 2)] = parseInt(hS.slice(i, i + 2), 16);
   return bA;
  }
  
  function pB(OT) {
   var SE = [];
   if (!OT || OT.length % 4) return;
   SE[0] = [];
   SE[1] = [];
   SE[2] = [];
   SE[3] = [];
   for (var j = 0; j < OT.length; j += 4) {
    SE[0][j / 4] = OT[j];
    SE[1][j / 4] = OT[j + 1];
    SE[2][j / 4] = OT[j + 2];
    SE[3][j / 4] = OT[j + 3];
   }
   return SE;
  }
  
  function uPB(PK) {
   var R = [];
   for (var j = 0; j < PK[0].length; j++) {
    R[R.length] = PK[0][j];
    R[R.length] = PK[1][j];
    R[R.length] = PK[2][j];
    R[R.length] = PK[3][j];
   }
   return R;
  }
  
  function fPT(PT) {
   var bpb = BB / 8;
   var i;
   if (typeof PT == "string" || PT.indexOf) {
    PT = PT.split("");
    for (i = 0; i < PT.length; i++) PT[i] = PT[i].charCodeAt(0) & 0xFF;
   }
   for (i = bpb - (PT.length % bpb); i > 0 && i < bpb; i--) PT[PT.length] = 0;
   return PT;
  }
  
  function gRB(hM) {
   var i;
   var bt = [];
   for (i = 0; i < hM; i++) bt[i] = Math.round(Math.random() * 255);
   return bt;
  }
  
  function rijndaelEncrypt(PT, Y, M) {
   var EY, i, abk;
   var bpb = BB / 8;
   var ct;
   if (!PT || !Y) return;
   if (Y.length * 8 != BS) return;
   if (M == "CBC") ct = gRB(bpb);
   else {
    M = "ECB";
    ct = [];
   }
   PT = fPT(PT);
   EY = YE(Y);
   for (var bk = 0; bk < PT.length / bpb; bk++) {
    abk = PT.slice(bk * bpb, (bk + 1) * bpb);
    if (M == "CBC") for (var i = 0; i < bpb; i++) abk[i] ^= ct[bk * bpb + i];
    ct = ct.concat(encrypt(abk, EY));
   }
   return ct;
  }
  
  function rijndaelDecrypt(CT, Y, M) {
   var EY;
   var bpb = BB / 8;
   var pt = [];
   var abk;
   var bk;
   if (!CT || !Y || typeof CT == "string") return;
   if (Y.length * 8 != BS) return;
   if (!M) M = "ECB";
   EY = YE(Y);
   for (bk = (CT.length / bpb) - 1; bk > 0; bk--) {
    abk = decrypt(CT.slice(bk * bpb, (bk + 1) * bpb), EY);
    if (M == "CBC") for (var i = 0; i < bpb; i++) pt[(bk - 1) * bpb + i] = abk[i] ^ CT[(bk - 1) * bpb + i];
    else pt = abk.concat(pt);
   }
   if (M == "ECB") pt = decrypt(CT.slice(0, bpb), EY).concat(pt);
   return pt;
  }
  
  function stringToByteArray(st) {
   var bA = [];
   for (var i = 0; i < st.length; i++) bA[i] = st.charCodeAt(i);
   return bA;
  }
  
  function genkey() {
   var j = "";
   while (1) {
    var i = Math.random().toString();
    j += i.substring(i.lastIndexOf(".") + 1);
    if (j.length > 31) return j.substring(0, 32);
   }
  }
  
  // AES Encryption (CTR) by Chris Veness
  // Source: http://www.movable-type.co.uk/scripts/aes.html
  var Aes = {};
  Aes.Cipher = function(input, w) {
   var Nb = 4;
   var Nr = w.length / Nb - 1;
   var state = [
    [],
    [],
    [],
    []
   ];
   for (var i = 0; i < 4 * Nb; i++) {
    state[i % 4][Math.floor(i / 4)] = input[i]
   }
   state = Aes.AddRoundKey(state, w, 0, Nb);
   for (var round = 1; round < Nr; round++) {
    state = Aes.SubBytes(state, Nb);
    state = Aes.ShiftRows(state, Nb);
    state = Aes.MixColumns(state, Nb);
    state = Aes.AddRoundKey(state, w, round, Nb)
   }
   state = Aes.SubBytes(state, Nb);
   state = Aes.ShiftRows(state, Nb);
   state = Aes.AddRoundKey(state, w, Nr, Nb);
   var output = new Array(4 * Nb);
   for (var i = 0; i < 4 * Nb; i++) {
    output[i] = state[i % 4][Math.floor(i / 4)]
   }
   return output
  };
  Aes.KeyExpansion = function(key) {
   var Nb = 4;
   var Nk = key.length / 4;
   var Nr = Nk + 6;
   var w = new Array(Nb * (Nr + 1));
   var temp = new Array(4);
   for (var i = 0; i < Nk; i++) {
    var r = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
    w[i] = r
   }
   for (var i = Nk; i < (Nb * (Nr + 1)); i++) {
    w[i] = new Array(4);
    for (var t = 0; t < 4; t++) {
     temp[t] = w[i - 1][t]
    }
    if (i % Nk == 0) {
     temp = Aes.SubWord(Aes.RotWord(temp));
     for (var t = 0; t < 4; t++) {
      temp[t] ^= Aes.Rcon[i / Nk][t]
     }
    } else {
     if (Nk > 6 && i % Nk == 4) {
      temp = Aes.SubWord(temp)
     }
    }
    for (var t = 0; t < 4; t++) {
     w[i][t] = w[i - Nk][t] ^ temp[t]
    }
   }
   return w
  };
  Aes.SubBytes = function(s, Nb) {
   for (var r = 0; r < 4; r++) {
    for (var c = 0; c < Nb; c++) {
     s[r][c] = Aes.Sbox[s[r][c]]
    }
   }
   return s
  };
  Aes.ShiftRows = function(s, Nb) {
   var t = new Array(4);
   for (var r = 1; r < 4; r++) {
    for (var c = 0; c < 4; c++) {
     t[c] = s[r][(c + r) % Nb]
    }
    for (var c = 0; c < 4; c++) {
     s[r][c] = t[c]
    }
   }
   return s
  };
  Aes.MixColumns = function(s, Nb) {
   for (var c = 0; c < 4; c++) {
    var a = new Array(4);
    var b = new Array(4);
    for (var i = 0; i < 4; i++) {
     a[i] = s[i][c];
     b[i] = s[i][c] & 128 ? s[i][c] << 1 ^ 283 : s[i][c] << 1
    }
    s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
    s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
    s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
    s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]
   }
   return s
  };
  Aes.AddRoundKey = function(state, w, rnd, Nb) {
   for (var r = 0; r < 4; r++) {
    for (var c = 0; c < Nb; c++) {
     state[r][c] ^= w[rnd * 4 + c][r]
    }
   }
   return state
  };
  Aes.SubWord = function(w) {
   for (var i = 0; i < 4; i++) {
    w[i] = Aes.Sbox[w[i]]
   }
   return w
  };
  Aes.RotWord = function(w) {
   var tmp = w[0];
   for (var i = 0; i < 3; i++) {
    w[i] = w[i + 1]
   }
   w[3] = tmp;
   return w
  };
  Aes.Sbox = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22];
  Aes.Rcon = [
   [0, 0, 0, 0],
   [1, 0, 0, 0],
   [2, 0, 0, 0],
   [4, 0, 0, 0],
   [8, 0, 0, 0],
   [16, 0, 0, 0],
   [32, 0, 0, 0],
   [64, 0, 0, 0],
   [128, 0, 0, 0],
   [27, 0, 0, 0],
   [54, 0, 0, 0]
  ];
  var AesCtr = {};
  AesCtr.encrypt = function(plaintext, password, nBits) {
   var blockSize = 16;
   if (!(nBits == 128 || nBits == 192 || nBits == 256)) {
    return ""
   }
   plaintext = Utf8.encode(plaintext);
   password = Utf8.encode(password);
   var nBytes = nBits / 8;
   var pwBytes = new Array(nBytes);
   for (var i = 0; i < nBytes; i++) {
    pwBytes[i] = isNaN(password.charCodeAt(i)) ? 0 : password.charCodeAt(i)
   }
   var key = Aes.Cipher(pwBytes, Aes.KeyExpansion(pwBytes));
   key = key.concat(key.slice(0, nBytes - 16));
   var counterBlock = new Array(blockSize);
   var nonce = (new Date()).getTime();
   var nonceSec = Math.floor(nonce / 1000);
   var nonceMs = nonce % 1000;
   for (var i = 0; i < 4; i++) {
    counterBlock[i] = (nonceSec >>> i * 8) & 255
   }
   for (var i = 0; i < 4; i++) {
    counterBlock[i + 4] = nonceMs & 255
   }
   var ctrTxt = "";
   for (var i = 0; i < 8; i++) {
    ctrTxt += String.fromCharCode(counterBlock[i])
   }
   var keySchedule = Aes.KeyExpansion(key);
   var blockCount = Math.ceil(plaintext.length / blockSize);
   var ciphertxt = new Array(blockCount);
   for (var b = 0; b < blockCount; b++) {
    for (var c = 0; c < 4; c++) {
     counterBlock[15 - c] = (b >>> c * 8) & 255
    }
    for (var c = 0; c < 4; c++) {
     counterBlock[15 - c - 4] = (b / 4294967296 >>> c * 8)
    }
    var cipherCntr = Aes.Cipher(counterBlock, keySchedule);
    var blockLength = b < blockCount - 1 ? blockSize : (plaintext.length - 1) % blockSize + 1;
    var cipherChar = new Array(blockLength);
    for (var i = 0; i < blockLength; i++) {
     cipherChar[i] = cipherCntr[i] ^ plaintext.charCodeAt(b * blockSize + i);
     cipherChar[i] = String.fromCharCode(cipherChar[i])
    }
    ciphertxt[b] = cipherChar.join("")
   }
   var ciphertext = ctrTxt + ciphertxt.join("");
   ciphertext = Base64.encode(ciphertext);
   return ciphertext
  };
  AesCtr.decrypt = function(ciphertext, password, nBits) {
   var blockSize = 16;
   if (!(nBits == 128 || nBits == 192 || nBits == 256)) {
    return ""
   }
   ciphertext = Base64.decode(ciphertext);
   password = Utf8.encode(password);
   var nBytes = nBits / 8;
   var pwBytes = new Array(nBytes);
   for (var i = 0; i < nBytes; i++) {
    pwBytes[i] = isNaN(password.charCodeAt(i)) ? 0 : password.charCodeAt(i)
   }
   var key = Aes.Cipher(pwBytes, Aes.KeyExpansion(pwBytes));
   key = key.concat(key.slice(0, nBytes - 16));
   var counterBlock = new Array(8);
   ctrTxt = ciphertext.slice(0, 8);
   for (var i = 0; i < 8; i++) {
    counterBlock[i] = ctrTxt.charCodeAt(i)
   }
   var keySchedule = Aes.KeyExpansion(key);
   var nBlocks = Math.ceil((ciphertext.length - 8) / blockSize);
   var ct = new Array(nBlocks);
   for (var b = 0; b < nBlocks; b++) {
    ct[b] = ciphertext.slice(8 + b * blockSize, 8 + b * blockSize + blockSize)
   }
   ciphertext = ct;
   var plaintxt = new Array(ciphertext.length);
   for (var b = 0; b < nBlocks; b++) {
    for (var c = 0; c < 4; c++) {
     counterBlock[15 - c] = ((b) >>> c * 8) & 255
    }
    for (var c = 0; c < 4; c++) {
     counterBlock[15 - c - 4] = (((b + 1) / 4294967296 - 1) >>> c * 8) & 255
    }
    var cipherCntr = Aes.Cipher(counterBlock, keySchedule);
    var plaintxtByte = new Array(ciphertext[b].length);
    for (var i = 0; i < ciphertext[b].length; i++) {
     plaintxtByte[i] = cipherCntr[i] ^ ciphertext[b].charCodeAt(i);
     plaintxtByte[i] = String.fromCharCode(plaintxtByte[i])
    }
    plaintxt[b] = plaintxtByte.join("")
   }
   var plaintext = plaintxt.join("");
   plaintext = Utf8.decode(plaintext);
   return plaintext
  };
  var Base64 = {};
  Base64.code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  Base64.encode = function(str, utf8encode) {
   utf8encode = (typeof utf8encode == "undefined") ? false : utf8encode;
   var o1, o2, o3, bits, h1, h2, h3, h4, e = [],
       pad = "",
       c, plain, coded;
   var b64 = Base64.code;
   plain = utf8encode ? str.encodeUTF8() : str;
   c = plain.length % 3;
   if (c > 0) {
    while (c++ < 3) {
     pad += "=";
     plain += "\0"
    }
   }
   for (c = 0; c < plain.length; c += 3) {
    o1 = plain.charCodeAt(c);
    o2 = plain.charCodeAt(c + 1);
    o3 = plain.charCodeAt(c + 2);
    bits = o1 << 16 | o2 << 8 | o3;
    h1 = bits >> 18 & 63;
    h2 = bits >> 12 & 63;
    h3 = bits >> 6 & 63;
    h4 = bits & 63;
    e[c / 3] = b64.charAt(h1) + b64.charAt(h2) + b64.charAt(h3) + b64.charAt(h4)
   }
   coded = e.join("");
   coded = coded.slice(0, coded.length - pad.length) + pad;
   return coded
  };
  Base64.decode = function(str, utf8decode) {
   utf8decode = (typeof utf8decode == "undefined") ? false : utf8decode;
   var o1, o2, o3, h1, h2, h3, h4, bits, d = [],
       plain, coded;
   var b64 = Base64.code;
   coded = utf8decode ? str.decodeUTF8() : str;
   for (var c = 0; c < coded.length; c += 4) {
    h1 = b64.indexOf(coded.charAt(c));
    h2 = b64.indexOf(coded.charAt(c + 1));
    h3 = b64.indexOf(coded.charAt(c + 2));
    h4 = b64.indexOf(coded.charAt(c + 3));
    bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;
    o1 = bits >>> 16 & 255;
    o2 = bits >>> 8 & 255;
    o3 = bits & 255;
    d[c / 4] = String.fromCharCode(o1, o2, o3);
    if (h4 == 64) {
     d[c / 4] = String.fromCharCode(o1, o2)
    }
    if (h3 == 64) {
     d[c / 4] = String.fromCharCode(o1)
    }
   }
   plain = d.join("");
   return utf8decode ? plain.decodeUTF8() : plain
  };
  var Utf8 = {};
  Utf8.encode = function(strUni) {
   var strUtf = strUni.replace(/[\u0080-\u07ff]/g, function(c) {
    var cc = c.charCodeAt(0);
    return String.fromCharCode(192 | cc >> 6, 128 | cc & 63)
   });
   strUtf = strUtf.replace(/[\u0800-\uffff]/g, function(c) {
    var cc = c.charCodeAt(0);
    return String.fromCharCode(224 | cc >> 12, 128 | cc >> 6 & 63, 128 | cc & 63)
   });
   return strUtf
  };
  Utf8.decode = function(strUtf) {
   var strUni = strUtf.replace(/[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g, function(c) {
    var cc = ((c.charCodeAt(0) & 15) << 12) | ((c.charCodeAt(1) & 63) << 6) | (c.charCodeAt(2) & 63);
    return String.fromCharCode(cc)
   });
   strUni = strUni.replace(/[\u00c0-\u00df][\u0080-\u00bf]/g, function(c) {
    var cc = (c.charCodeAt(0) & 31) << 6 | c.charCodeAt(1) & 63;
    return String.fromCharCode(cc)
   });
   return strUni
  };
  
  // Block TEA Encryption (xxtea) by Chris Veness
  // Source: http://www.movable-type.co.uk/scripts/tea-block.html
  var Tea = {};
  Tea.encrypt = function(plaintext, password) {
   if (plaintext.length == 0) {
    return ("")
   }
   var v = Tea.strToLongs(Utf8.encode(plaintext));
   if (v.length <= 1) {
    v[1] = 0
   }
   var k = Tea.strToLongs(Utf8.encode(password).slice(0, 16));
   var n = v.length;
   var z = v[n - 1],
       y = v[0],
       delta = 2654435769;
   var mx, e, q = Math.floor(6 + 52 / n),
       sum = 0;
   while (q-- > 0) {
    sum += delta;
    e = sum >>> 2 & 3;
    for (var p = 0; p < n; p++) {
     y = v[(p + 1) % n];
     mx = (z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
     z = v[p] += mx
    }
   }
   var ciphertext = Tea.longsToStr(v);
   return Base64.encode(ciphertext)
  };
  Tea.decrypt = function(ciphertext, password) {
   if (ciphertext.length == 0) {
    return ("")
   }
   var v = Tea.strToLongs(Base64.decode(ciphertext));
   var k = Tea.strToLongs(Utf8.encode(password).slice(0, 16));
   var n = v.length;
   var z = v[n - 1],
       y = v[0],
       delta = 2654435769;
   var mx, e, q = Math.floor(6 + 52 / n),
       sum = q * delta;
   while (sum != 0) {
    e = sum >>> 2 & 3;
    for (var p = n - 1; p >= 0; p--) {
     z = v[p > 0 ? p - 1 : n - 1];
     mx = (z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
     y = v[p] -= mx
    }
    sum -= delta
   }
   var plaintext = Tea.longsToStr(v);
   plaintext = plaintext.replace(/\0+$/, "");
   return Utf8.decode(plaintext)
  };
  Tea.strToLongs = function(s) {
   var l = new Array(Math.ceil(s.length / 4));
   for (var i = 0; i < l.length; i++) {
    l[i] = s.charCodeAt(i * 4) + (s.charCodeAt(i * 4 + 1) << 8) + (s.charCodeAt(i * 4 + 2) << 16) + (s.charCodeAt(i * 4 + 3) << 24)
   }
   return l
  };
  Tea.longsToStr = function(l) {
   var a = new Array(l.length);
   for (var i = 0; i < l.length; i++) {
    a[i] = String.fromCharCode(l[i] & 255, l[i] >>> 8 & 255, l[i] >>> 16 & 255, l[i] >>> 24 & 255)
   }
   return a.join("")
  };
  var Base64 = {};
  Base64.code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  Base64.encode = function(str, utf8encode) {
   utf8encode = (typeof utf8encode == "undefined") ? false : utf8encode;
   var o1, o2, o3, bits, h1, h2, h3, h4, e = [],
       pad = "",
       c, plain, coded;
   var b64 = Base64.code;
   plain = utf8encode ? Utf8.encode(str) : str;
   c = plain.length % 3;
   if (c > 0) {
    while (c++ < 3) {
     pad += "=";
     plain += "\0"
    }
   }
   for (c = 0; c < plain.length; c += 3) {
    o1 = plain.charCodeAt(c);
    o2 = plain.charCodeAt(c + 1);
    o3 = plain.charCodeAt(c + 2);
    bits = o1 << 16 | o2 << 8 | o3;
    h1 = bits >> 18 & 63;
    h2 = bits >> 12 & 63;
    h3 = bits >> 6 & 63;
    h4 = bits & 63;
    e[c / 3] = b64.charAt(h1) + b64.charAt(h2) + b64.charAt(h3) + b64.charAt(h4)
   }
   coded = e.join("");
   coded = coded.slice(0, coded.length - pad.length) + pad;
   return coded
  };
  Base64.decode = function(str, utf8decode) {
   utf8decode = (typeof utf8decode == "undefined") ? false : utf8decode;
   var o1, o2, o3, h1, h2, h3, h4, bits, d = [],
       plain, coded;
   var b64 = Base64.code;
   coded = utf8decode ? Utf8.decode(str) : str;
   for (var c = 0; c < coded.length; c += 4) {
    h1 = b64.indexOf(coded.charAt(c));
    h2 = b64.indexOf(coded.charAt(c + 1));
    h3 = b64.indexOf(coded.charAt(c + 2));
    h4 = b64.indexOf(coded.charAt(c + 3));
    bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;
    o1 = bits >>> 16 & 255;
    o2 = bits >>> 8 & 255;
    o3 = bits & 255;
    d[c / 4] = String.fromCharCode(o1, o2, o3);
    if (h4 == 64) {
     d[c / 4] = String.fromCharCode(o1, o2)
    }
    if (h3 == 64) {
     d[c / 4] = String.fromCharCode(o1)
    }
   }
   plain = d.join("");
   return utf8decode ? Utf8.decode(plain) : plain
  };
  var Utf8 = {};
  Utf8.encode = function(strUni) {
   var strUtf = strUni.replace(/[\u0080-\u07ff]/g, function(c) {
    var cc = c.charCodeAt(0);
    return String.fromCharCode(192 | cc >> 6, 128 | cc & 63)
   });
   strUtf = strUtf.replace(/[\u0800-\uffff]/g, function(c) {
    var cc = c.charCodeAt(0);
    return String.fromCharCode(224 | cc >> 12, 128 | cc >> 6 & 63, 128 | cc & 63)
   });
   return strUtf
  };
  Utf8.decode = function(strUtf) {
   var strUni = strUtf.replace(/[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g, function(c) {
    var cc = ((c.charCodeAt(0) & 15) << 12) | ((c.charCodeAt(1) & 63) << 6) | (c.charCodeAt(2) & 63);
    return String.fromCharCode(cc)
   });
   strUni = strUni.replace(/[\u00c0-\u00df][\u0080-\u00bf]/g, function(c) {
    var cc = (c.charCodeAt(0) & 31) << 6 | c.charCodeAt(1) & 63;
    return String.fromCharCode(cc)
   });
   return strUni
  };