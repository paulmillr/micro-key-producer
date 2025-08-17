export const DER_VECTORS = [
  // Rust-crypto/formats
  {
    name: 'ed25519-encpriv-aes256-pbkdf2-sha256',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGbMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAh52YLnDfkaiAICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEELLQLXiy79nf9pTPjgr0CSUEQNDN
bHcPS7hxdkIjBcF0AYCeImZ0znQYXSIb/aqVBpiQyIgvzgKwXUG8v1SwNVlbzUFU
syWTcIRpuGqs+IFaeys=
-----END ENCRYPTED PRIVATE KEY-----`,
  },
  {
    name: 'ed25519-encpriv-aes256-scrypt',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGTME8GCSqGSIb3DQEFDTBCMCEGCSsGAQQB2kcECzAUBAjmIR4jSK1p4AICQAAC
AQgCAQEwHQYJYIZIAWUDBAEqBBCb0KYlHyJU+f1ZY4h8J88BBEDMYrp3PA9JX6s2
aOT8782wjnig7hXgoVAT9iq+CNqnQgZe6zZtbmyYzDsOfmm9yGHIiv648D26Hixt
mdBtFzYM
-----END ENCRYPTED PRIVATE KEY-----`,
  },
  {
    name: 'ed25519-priv-pkcs8v1',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBftnHPp22SewYmmEoMcX8VwI4IHwaqd+9LFPj/15eqF
-----END PRIVATE KEY-----`,
    decoded: {
      version: 0n,
      algorithm: { info: { TAG: 'Ed25519', data: null } },
      privateKey: {
        TAG: 'raw',
        data: new Uint8Array([
          23, 237, 156, 115, 233, 219, 100, 158, 193, 137, 166, 18, 131, 28, 95, 197, 112, 35, 130,
          7, 193, 170, 157, 251, 210, 197, 62, 63, 245, 229, 234, 133,
        ]),
      },
      attributes: undefined,
      publicKey: undefined,
    },
  },
  {
    name: 'ed25519-priv-pkcs8v2',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB
Z9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PRIVATE KEY-----`,
    decoded: {
      version: 1n,
      algorithm: { info: { TAG: 'Ed25519', data: null } },
      privateKey: {
        TAG: 'raw',
        data: new Uint8Array([
          212, 238, 114, 219, 249, 19, 88, 74, 213, 182, 216, 241, 247, 105, 248, 173, 58, 254, 124,
          40, 203, 241, 212, 251, 224, 151, 168, 143, 68, 117, 88, 66,
        ]),
      },
      attributes: [
        new Uint8Array([
          48, 29, 6, 10, 42, 134, 72, 134, 247, 13, 1, 9, 9, 20, 49, 15, 12, 13, 67, 117, 114, 100,
          108, 101, 32, 67, 104, 97, 105, 114, 115,
        ]),
      ],
      // attributes: [
      //   {
      //     attribute: {
      //       TAG: 'friendlyName2',
      //       data: [{ TAG: 'utf8', data: 'Curdle Chairs' }],
      //     },
      //   },
      // ],
      publicKey: new Uint8Array([
        25, 191, 68, 9, 105, 132, 205, 254, 133, 65, 186, 193, 103, 220, 59, 150, 200, 80, 134, 170,
        48, 182, 182, 203, 12, 92, 56, 173, 112, 49, 102, 225,
      ]),
      /*
    0:d=0  hl=2 l= 114 cons: SEQUENCE
    2:d=1  hl=2 l=   1 prim: INTEGER           :01
    5:d=1  hl=2 l=   5 cons: SEQUENCE
    7:d=2  hl=2 l=   3 prim: OBJECT            :ED25519
   12:d=1  hl=2 l=  34 prim: OCTET STRING      [HEX DUMP]:0420D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842
   48:d=1  hl=2 l=  31 cons: cont [ 0 ]
   50:d=2  hl=2 l=  29 cons: SEQUENCE
   52:d=3  hl=2 l=  10 prim: OBJECT            :1.2.840.113549.1.9.9.20
   64:d=3  hl=2 l=  15 cons: SET
   66:d=4  hl=2 l=  13 prim: UTF8STRING        :Curdle Chairs
   81:d=1  hl=2 l=  33 prim: cont [ 1 ]
    */
    },
  },
  {
    name: 'ed25519-pub',
    type: '???',
    pem: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEATSkWfz8ZEqb3rfopOgUaFcBexnuPFyZ7HFVQ3OhTvQ0=
-----END PUBLIC KEY-----`,
    decoded: {
      algorithm: { info: { TAG: 'Ed25519', data: null } },
      publicKey: new Uint8Array([
        77, 41, 22, 127, 63, 25, 18, 166, 247, 173, 250, 41, 58, 5, 26, 21, 192, 94, 198, 123, 143,
        23, 38, 123, 28, 85, 80, 220, 232, 83, 189, 13,
      ]),
    },
  },
  {
    name: 'p256-priv',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaWJBcVYaYzQN4OfY
afKgVJJVjhoEhotqn4VKhmeIGI2hRANCAAQcrP+1Xy8s79idies3SyaBFSRSgC3u
oJkWBoE32DnPf8SBpESSME1+9mrBF77+g6jQjxVfK1L59hjdRHApBI4P
-----END PRIVATE KEY-----`,
    decoded: {
      version: 0n,
      algorithm: {
        info: {
          TAG: 'EC',
          data: { TAG: 'namedCurve', data: '1.2.840.10045.3.1.7' },
        },
      },
      privateKey: {
        TAG: 'struct',
        data: {
          version: 1n,
          privateKey: new Uint8Array([
            105, 98, 65, 113, 86, 26, 99, 52, 13, 224, 231, 216, 105, 242, 160, 84, 146, 85, 142,
            26, 4, 134, 139, 106, 159, 133, 74, 134, 103, 136, 24, 141,
          ]),
          parameters: undefined,
          publicKey: new Uint8Array([
            4, 28, 172, 255, 181, 95, 47, 44, 239, 216, 157, 137, 235, 55, 75, 38, 129, 21, 36, 82,
            128, 45, 238, 160, 153, 22, 6, 129, 55, 216, 57, 207, 127, 196, 129, 164, 68, 146, 48,
            77, 126, 246, 106, 193, 23, 190, 254, 131, 168, 208, 143, 21, 95, 43, 82, 249, 246, 24,
            221, 68, 112, 41, 4, 142, 15,
          ]),
        },
      },
      attributes: undefined,
      publicKey: undefined,
    },
  },
  {
    name: 'p256-pub',
    pem: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHKz/tV8vLO/YnYnrN0smgRUkUoAt
7qCZFgaBN9g5z3/EgaREkjBNfvZqwRe+/oOo0I8VXytS+fYY3URwKQSODw==
-----END PUBLIC KEY-----`,
    decoded: {
      algorithm: {
        info: {
          TAG: 'EC',
          data: { TAG: 'namedCurve', data: '1.2.840.10045.3.1.7' },
        },
      },
      publicKey: new Uint8Array([
        4, 28, 172, 255, 181, 95, 47, 44, 239, 216, 157, 137, 235, 55, 75, 38, 129, 21, 36, 82, 128,
        45, 238, 160, 153, 22, 6, 129, 55, 216, 57, 207, 127, 196, 129, 164, 68, 146, 48, 77, 126,
        246, 106, 193, 23, 190, 254, 131, 168, 208, 143, 21, 95, 43, 82, 249, 246, 24, 221, 68, 112,
        41, 4, 142, 15,
      ]),
    },
  },
  // We don't support rsa, but it is nice to test that we don't accidentally decode it into EC key
  {
    name: 'rsa2048-priv',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2xCxRXxCmqvKC
xj7b4kJDoXDz+iYzvUgzY39Hyk9vNuA6XSnvwxkayA85DYdLOeMPQU/Owfyg7YHl
R+3CzTgsdvYckBiXPbn6U3lyp8cB9rd+CYLfwV/AGSfuXnzZS09Zn/BwE6fIKBvf
Ity8mtfKu3xDEcmC9Y7bchOtRVizMiZtdDrtgZLRiEytuLFHOaja2mbclwgG2ces
RQyxPQ18V1+xmFNPxhvEG8DwV04OATDHu7+9/cn2puLj4q/xy+rIm6V4hFKNVc+w
gyeh6MifTgA88oiOkzJB2daVvLus3JC0Tj4JX6NwWOolsT9eKVy+rG3oOKuMUK9h
4piXW4cvAgMBAAECggEAfsyDYsDtsHQRZCFeIvdKudkboGkAcAz2NpDlEU2O5r3P
uy4/lhRpKmd6CD8Wil5S5ZaOZAe52XxuDkBk+C2gt1ihTxe5t9QfX0jijWVRcE9W
5p56qfpjD8dkKMBtJeRV3PxVt6wrT3ZkP97T/hX/eKuyfmWsxKrQvfbbJ+9gppEM
XEoIXtQydasZwdmXoyxu/8598tGTX25gHu3hYaErXMJ8oh+B0smcPR6gjpDjBTqw
m++nJN7w0MOjwel0DA2fdhJqFJ7Aqn2AeCBUhCVNlR2wfEz5H7ZFTAlliP1ZJNur
6zWcogJSaNAE+dZus9b3rcETm61A8W3eY54RZHN2wQKBgQDcwGEkLU6Sr67nKsUT
ymW593A2+b1+Dm5hRhp+92VCJewVPH5cMaYVem5aE/9uF46HWMHLM9nWu+MXnvGJ
mOQi7Ny+149Oz9vl9PzYrsLJ0NyGRzypvRbZ0jjSH7Xd776xQ8ph0L1qqNkfM6CX
eQ6WQNvJEIXcXyY0O6MTj2stZwKBgQDT8xR1fkDpVINvkr4kI2ry8NoEo0ZTwYCv
Z+lgCG2T/eZcsj79nQk3R2L1mB42GEmvaM3XU5T/ak4G62myCeQijbLfpw5A9/l1
ClKBdmR7eI0OV3eiy4si480mf/cLTzsC06r7DhjFkKVksDGIsKpfxIFWsHYiIUJD
vRIn76fy+QKBgQDOaLesGw0QDWNuVUiHU8XAmEP9s5DicF33aJRXyb2Nl2XjCXhh
fi78gEj0wyQgbbhgh7ZU6Xuz1GTn7j+M2D/hBDb33xjpqWPE5kkR1n7eNAQvLibj
06GtNGra1rm39ncIywlOYt7p/01dZmmvmIryJV0c6O0xfGp9hpHaNU0S2wKBgCX2
5ZRCIChrTfu/QjXA7lhD0hmAkYlRINbKeyALgm0+znOOLgBJj6wKKmypacfww8oa
sLxAKXEyvnU4177fTLDvxrmO99ulT1aqmaq85TTEnCeUfUZ4xRxjx4x84WhyMbTI
61h65u8EgMuvT8AXPP1Yen5nr1FfubnedREYOXIpAoGAMZlUBtQGIHyt6uo1s40E
DF+Kmhrggn6e0GsVPYO2ghk1tLNqgr6dVseRtYwnJxpXk9U6HWV8CJl5YLFDPlFx
mH9FLxRKfHIwbWPh0//Atxt1qwjy5FpILpiEUcvkeOEusijQdFbJJLZvbO0EjYU/
Uz4xpoYU8cPObY7JmDznKvc=
-----END PRIVATE KEY-----`,
    notImplemented: true,
  },
  {
    name: 'rsa2048-pub',
    pem: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtsQsUV8QpqrygsY+2+JC
Q6Fw8/omM71IM2N/R8pPbzbgOl0p78MZGsgPOQ2HSznjD0FPzsH8oO2B5Uftws04
LHb2HJAYlz25+lN5cqfHAfa3fgmC38FfwBkn7l582UtPWZ/wcBOnyCgb3yLcvJrX
yrt8QxHJgvWO23ITrUVYszImbXQ67YGS0YhMrbixRzmo2tpm3JcIBtnHrEUMsT0N
fFdfsZhTT8YbxBvA8FdODgEwx7u/vf3J9qbi4+Kv8cvqyJuleIRSjVXPsIMnoejI
n04APPKIjpMyQdnWlby7rNyQtE4+CV+jcFjqJbE/Xilcvqxt6DirjFCvYeKYl1uH
LwIDAQAB
-----END PUBLIC KEY-----`,
    decoded: {
      algorithm: { info: { TAG: 'rsaEncryption', data: null } },
      publicKey: new Uint8Array([
        48, 130, 1, 10, 2, 130, 1, 1, 0, 182, 196, 44, 81, 95, 16, 166, 170, 242, 130, 198, 62, 219,
        226, 66, 67, 161, 112, 243, 250, 38, 51, 189, 72, 51, 99, 127, 71, 202, 79, 111, 54, 224,
        58, 93, 41, 239, 195, 25, 26, 200, 15, 57, 13, 135, 75, 57, 227, 15, 65, 79, 206, 193, 252,
        160, 237, 129, 229, 71, 237, 194, 205, 56, 44, 118, 246, 28, 144, 24, 151, 61, 185, 250, 83,
        121, 114, 167, 199, 1, 246, 183, 126, 9, 130, 223, 193, 95, 192, 25, 39, 238, 94, 124, 217,
        75, 79, 89, 159, 240, 112, 19, 167, 200, 40, 27, 223, 34, 220, 188, 154, 215, 202, 187, 124,
        67, 17, 201, 130, 245, 142, 219, 114, 19, 173, 69, 88, 179, 50, 38, 109, 116, 58, 237, 129,
        146, 209, 136, 76, 173, 184, 177, 71, 57, 168, 218, 218, 102, 220, 151, 8, 6, 217, 199, 172,
        69, 12, 177, 61, 13, 124, 87, 95, 177, 152, 83, 79, 198, 27, 196, 27, 192, 240, 87, 78, 14,
        1, 48, 199, 187, 191, 189, 253, 201, 246, 166, 226, 227, 226, 175, 241, 203, 234, 200, 155,
        165, 120, 132, 82, 141, 85, 207, 176, 131, 39, 161, 232, 200, 159, 78, 0, 60, 242, 136, 142,
        147, 50, 65, 217, 214, 149, 188, 187, 172, 220, 144, 180, 78, 62, 9, 95, 163, 112, 88, 234,
        37, 177, 63, 94, 41, 92, 190, 172, 109, 232, 56, 171, 140, 80, 175, 97, 226, 152, 151, 91,
        135, 47, 2, 3, 1, 0, 1,
      ]),
    },
  },
  {
    name: 'x25519-priv',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIHBgJSkzrG56SpsOsmMsWgQKhyV624aaPszD0WtyTyZH
-----END PRIVATE KEY-----`,
    decoded: {
      version: 0n,
      algorithm: { info: { TAG: 'X25519', data: null } },
      privateKey: {
        TAG: 'raw',
        data: new Uint8Array([
          112, 96, 37, 41, 51, 172, 110, 122, 74, 155, 14, 178, 99, 44, 90, 4, 10, 135, 37, 122,
          219, 134, 154, 62, 204, 195, 209, 107, 114, 79, 38, 71,
        ]),
      },
      attributes: undefined,
      publicKey: undefined,
    },
  },
  {
    name: 'ed25519-pub',
    type: 'spki',
    pem: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEATSkWfz8ZEqb3rfopOgUaFcBexnuPFyZ7HFVQ3OhTvQ0=
-----END PUBLIC KEY-----`,
    decoded: {
      algorithm: { info: { TAG: 'Ed25519', data: null } },
      publicKey: new Uint8Array([
        77, 41, 22, 127, 63, 25, 18, 166, 247, 173, 250, 41, 58, 5, 26, 21, 192, 94, 198, 123, 143,
        23, 38, 123, 28, 85, 80, 220, 232, 83, 189, 13,
      ]),
    },
  },
  {
    name: 'p256-pub',
    type: 'spki',
    pem: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHKz/tV8vLO/YnYnrN0smgRUkUoAt
7qCZFgaBN9g5z3/EgaREkjBNfvZqwRe+/oOo0I8VXytS+fYY3URwKQSODw==
-----END PUBLIC KEY-----`,
    decoded: {
      algorithm: {
        info: {
          TAG: 'EC',
          data: { TAG: 'namedCurve', data: '1.2.840.10045.3.1.7' },
        },
      },
      publicKey: new Uint8Array([
        4, 28, 172, 255, 181, 95, 47, 44, 239, 216, 157, 137, 235, 55, 75, 38, 129, 21, 36, 82, 128,
        45, 238, 160, 153, 22, 6, 129, 55, 216, 57, 207, 127, 196, 129, 164, 68, 146, 48, 77, 126,
        246, 106, 193, 23, 190, 254, 131, 168, 208, 143, 21, 95, 43, 82, 249, 246, 24, 221, 68, 112,
        41, 4, 142, 15,
      ]),
    },
  },
  {
    name: 'rsa2048-pub',
    type: 'spki',
    pem: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtsQsUV8QpqrygsY+2+JC
Q6Fw8/omM71IM2N/R8pPbzbgOl0p78MZGsgPOQ2HSznjD0FPzsH8oO2B5Uftws04
LHb2HJAYlz25+lN5cqfHAfa3fgmC38FfwBkn7l582UtPWZ/wcBOnyCgb3yLcvJrX
yrt8QxHJgvWO23ITrUVYszImbXQ67YGS0YhMrbixRzmo2tpm3JcIBtnHrEUMsT0N
fFdfsZhTT8YbxBvA8FdODgEwx7u/vf3J9qbi4+Kv8cvqyJuleIRSjVXPsIMnoejI
n04APPKIjpMyQdnWlby7rNyQtE4+CV+jcFjqJbE/Xilcvqxt6DirjFCvYeKYl1uH
LwIDAQAB
-----END PUBLIC KEY-----`,
  },
  // pyca/cryptography
  {
    name: 'explicit_parameters_private_key',
    pem: `-----BEGIN EC PRIVATE KEY-----
MIIBaAIBAQQgoIAlsArFMdyIAGre7kgA0D4fvM+Dibt9XSdtFxhuPrWggfowgfcC
AQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA///////////////+
MFsEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57Pr
vVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEE
axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54W
K84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8
YyVRAgEBoUQDQgAEhIXBZutCVz1ULBu1Mq1Hg1FV0wgYADGMRvYdC1zR1nqvVsmB
yYka/ElVXwRwUAKxwhbXXt2kTvpZEAG/wjOn3Q==
-----END EC PRIVATE KEY-----`,
  },
  {
    name: 'explicit_parameters_wap_wsg_idm_ecid_wtls11_private_key',
    pem: `-----BEGIN EC PRIVATE KEY-----
MIIBSAIBAQQeAOgdbe7dchFPZAojhztGgDWQqwyZHjLneCvhSvBfoIHgMIHdAgEB
MB0GByqGSM49AQIwEgICAOkGCSqGSM49AQIDAgIBSjBXBB4AAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAEEHgBmZH7ebDMsf4wJI7tYITszOyDpzkKB/hFffY+Q
rQMVAHTVn/B/a0E9DqFLNEsgotsEm1DDBD0EAPrJ38usgxO7ITnxu3Vf72W8OR+L
Nvj463Nx/VWLAQBqCKQZAzUGeOWFKL6/igvv+GenyjZxb34B+BBSAh4BAAAAAAAA
AAAAAAAAAAAT6XTnL4ppIgMdJgPP4NcCAQKhQAM+AAQAITc5rTBkBHaMSOuhKb8z
c/hoCZIQEQp0F3fawnMBi82rKn67H56ZrXX7dWzL5yFGmleInGphYwDo+2A=
-----END EC PRIVATE KEY-----`,
  },
  {
    name: 'secp128r1_private_key',
    pem: `-----BEGIN EC PRIVATE KEY-----
MEQCAQEEEGqA3EQW0B/63PyiwCa4bg2gBwYFK4EEAByhJAMiAASL133VyEjU3FUh
9sq37xm62q/GWxp1Q4t2iOpuBzBrBQ==
-----END EC PRIVATE KEY-----`,
  },
  {
    name: 'secp256k1-explicit-no-seed',
    pem: `-----BEGIN PRIVATE KEY-----
MIIBYQIBADCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA////////////
/////////////////////////v///C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEE
eb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio
/Re0SKaFVBmcR9CP+xDUuAIhAP////////////////////66rtzmr0igO7/SXozQ
NkFBAgEBBG0wawIBAQQg0fB/gU29JVUd5ElgaN2mwKFJGvzItUe0T2StN0Ezet6h
RANCAATF+z+muwej787mrhx40dzqUKtEqk3DgqAWw0sbY3nO/VjBpSJzsSLWIFyN
VGWxRUM46VmGL3sHMIMAXJ0vEH0d
-----END PRIVATE KEY-----`,
    decoded: {
      version: 0n,
      algorithm: {
        info: {
          TAG: 'EC',
          data: {
            TAG: 'specifiedCurve',
            data: {
              version: 1n,
              fieldId: {
                info: {
                  TAG: 'primeField',
                  data: 115792089237316195423570985008687907853269984665640564039457584007908834671663n,
                },
              },
              curve: {
                a: new Uint8Array([
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0,
                ]),
                b: new Uint8Array([
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 7,
                ]),
                seed: undefined,
              },
              base: new Uint8Array([
                4, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2,
                155, 252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152, 72, 58, 218,
                119, 38, 163, 196, 101, 93, 164, 251, 252, 14, 17, 8, 168, 253, 23, 180, 72, 166,
                133, 84, 25, 156, 71, 208, 143, 251, 16, 212, 184,
              ]),
              order:
                115792089237316195423570985008687907852837564279074904382605163141518161494337n,
              cofactor: 1n,
              hash: undefined,
              rest: Uint8Array.of(),
            },
          },
        },
      },
      privateKey: {
        TAG: 'struct',
        data: {
          version: 1n,
          privateKey: new Uint8Array([
            209, 240, 127, 129, 77, 189, 37, 85, 29, 228, 73, 96, 104, 221, 166, 192, 161, 73, 26,
            252, 200, 181, 71, 180, 79, 100, 173, 55, 65, 51, 122, 222,
          ]),
          parameters: undefined,
          publicKey: new Uint8Array([
            4, 197, 251, 63, 166, 187, 7, 163, 239, 206, 230, 174, 28, 120, 209, 220, 234, 80, 171,
            68, 170, 77, 195, 130, 160, 22, 195, 75, 27, 99, 121, 206, 253, 88, 193, 165, 34, 115,
            177, 34, 214, 32, 92, 141, 84, 101, 177, 69, 67, 56, 233, 89, 134, 47, 123, 7, 48, 131,
            0, 92, 157, 47, 16, 125, 29,
          ]),
        },
      },
      attributes: undefined,
      publicKey: undefined,
    },
  },
  {
    name: 'secp256k1-pub-explicit-no-seed',
    pem: `-----BEGIN PUBLIC KEY-----
MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA////////////////
/////////////////////v///C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5m
fvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0
SKaFVBmcR9CP+xDUuAIhAP////////////////////66rtzmr0igO7/SXozQNkFB
AgEBA0IABMX7P6a7B6PvzuauHHjR3OpQq0SqTcOCoBbDSxtjec79WMGlInOxItYg
XI1UZbFFQzjpWYYvewcwgwBcnS8QfR0=
-----END PUBLIC KEY-----`,
    decoded: {
      algorithm: {
        info: {
          TAG: 'EC',
          data: {
            TAG: 'specifiedCurve',
            data: {
              version: 1n,
              fieldId: {
                info: {
                  TAG: 'primeField',
                  data: 115792089237316195423570985008687907853269984665640564039457584007908834671663n,
                },
              },
              curve: {
                a: new Uint8Array([
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0,
                ]),
                b: new Uint8Array([
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 7,
                ]),
                seed: undefined,
              },
              base: new Uint8Array([
                4, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2,
                155, 252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152, 72, 58, 218,
                119, 38, 163, 196, 101, 93, 164, 251, 252, 14, 17, 8, 168, 253, 23, 180, 72, 166,
                133, 84, 25, 156, 71, 208, 143, 251, 16, 212, 184,
              ]),
              order:
                115792089237316195423570985008687907852837564279074904382605163141518161494337n,
              cofactor: 1n,
              hash: undefined,
              rest: Uint8Array.of(),
            },
          },
        },
      },
      publicKey: new Uint8Array([
        4, 197, 251, 63, 166, 187, 7, 163, 239, 206, 230, 174, 28, 120, 209, 220, 234, 80, 171, 68,
        170, 77, 195, 130, 160, 22, 195, 75, 27, 99, 121, 206, 253, 88, 193, 165, 34, 115, 177, 34,
        214, 32, 92, 141, 84, 101, 177, 69, 67, 56, 233, 89, 134, 47, 123, 7, 48, 131, 0, 92, 157,
        47, 16, 125, 29,
      ]),
    },
  },
  {
    name: 'secp256r1-explicit-no-seed',
    pem: `-----BEGIN PRIVATE KEY-----
MIIBYQIBADCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////wAAAAEA
AAAAAAAAAAAAAAD///////////////8wRAQg/////wAAAAEAAAAAAAAAAAAAAAD/
//////////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLBEEE
axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54W
K84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8
YyVRAgEBBG0wawIBAQQgsR15A3k6KPVE303H1m4DEH6XJhjMvvhPWN4VrRCSdLeh
RANCAARkJWmeqojxqcbDHsnkDszH1K1VvfgJhDNsBQHkMgHUjZrbY3268a5/EvBO
U2CftfRxuAe02xjg0wU3zks7NaCb
-----END PRIVATE KEY-----`,
  },
  {
    name: 'secp256r1-explicit-seed',
    pem: `-----BEGIN PRIVATE KEY-----
MIIBeQIBADCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAAB
AAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA
///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMV
AMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg
9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8A
AAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBBG0wawIBAQQg2iYcnTtVn5DB
X9NKoAWnvMVXU2MorY2hCT4rN0sQG7ahRANCAARbHCXJP9mtfMEf46dFCDcCVW1q
sZgc0jTt9GKB/o1Rz8UoxyyWWxzX+lW402CpnNqZbKGVs0MuhZxv9BsDdMsY
-----END PRIVATE KEY-----`,
  },
  {
    name: 'secp256r1-pub-explicit-no-seed',
    pem: `-----BEGIN PUBLIC KEY-----
MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAA
AAAAAAAAAAD///////////////8wRAQg/////wAAAAEAAAAAAAAAAAAAAAD/////
//////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLBEEEaxfR
8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84z
V2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVR
AgEBA0IABGQlaZ6qiPGpxsMeyeQOzMfUrVW9+AmEM2wFAeQyAdSNmttjfbrxrn8S
8E5TYJ+19HG4B7TbGODTBTfOSzs1oJs=
-----END PUBLIC KEY-----`,
  },
  {
    name: 'secp256r1-pub-explicit-seed',
    pem: `-----BEGIN PUBLIC KEY-----
MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAA
AAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA////
///////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSd
NgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5
RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA
//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABFscJck/2a18wR/jp0UINwJV
bWqxmBzSNO30YoH+jVHPxSjHLJZbHNf6VbjTYKmc2plsoZWzQy6FnG/0GwN0yxg=
-----END PUBLIC KEY-----`,
  },
  {
    name: 'secp384r1-explicit-no-seed',
    pem: `-----BEGIN PRIVATE KEY-----
MIIB9QIBADCCAU0GByqGSM49AgEwggFAAgEBMDwGByqGSM49AQECMQD/////////
/////////////////////////////////v////8AAAAAAAAAAP////8wZAQw////
//////////////////////////////////////7/////AAAAAAAAAAD////8BDCz
MS+n4j7n5JiOBWvj+C0ZGB2cbv6BQRIDFAiPUBOHWsZWOY2KLtGdKoXI7dPsKu8E
YQSqh8oivosFN46xxx7zIK10bh07Younm5hZ90HgglQqOFUC8l2/VSlsOlReOHJ2
Crc2F95KliYsb12emL+Sktwp+PQdvSiaFHzp2jETtfC4wApgsc4dfoGdekMdfJDq
Dl8CMQD////////////////////////////////HY02B9Dct31gaDbJIsKd67OwZ
aszFKXMCAQEEgZ4wgZsCAQEEMP3yCnX3tWWsI5ScYiVMB4FN69h2mfxzECqxrePl
BUH68ozPkgB0y4UyIcUMn8sGHqFkA2IABP9QJ2J6GAT/BbPqr2M5mS+6kEJ7M1DS
gTVhuR3LX4eK5g2n0YWD1yeGjjg/fZRgqWnJ9DVMR2z6c9cMpXyUGHuuQlEolIzv
Nlj0Ox1nVti9N3bIXgSc/d7PBlWTThshVA==
-----END PRIVATE KEY-----`,
  },
  {
    name: 'secp384r1-explicit-seed',
    pem: `-----BEGIN PRIVATE KEY-----
MIICDAIBADCCAWQGByqGSM49AgEwggFXAgEBMDwGByqGSM49AQECMQD/////////
/////////////////////////////////v////8AAAAAAAAAAP////8wewQw////
//////////////////////////////////////7/////AAAAAAAAAAD////8BDCz
MS+n4j7n5JiOBWvj+C0ZGB2cbv6BQRIDFAiPUBOHWsZWOY2KLtGdKoXI7dPsKu8D
FQCjNZJqoxmieh0AiWpnc6SCes2scwRhBKqHyiK+iwU3jrHHHvMgrXRuHTtii6eb
mFn3QeCCVCo4VQLyXb9VKWw6VF44cnYKtzYX3kqWJixvXZ6Yv5KS3Cn49B29KJoU
fOnaMRO18LjACmCxzh1+gZ16Qx18kOoOXwIxAP//////////////////////////
/////8djTYH0Ny3fWBoNskiwp3rs7BlqzMUpcwIBAQSBnjCBmwIBAQQwPKjQ9aIk
HbtFJwY4V91r/G4wU3MSdTJMIn4SVTch5Ata0Ar++W74TcJqRo6KsiTqoWQDYgAE
8SpH9fXRoy5xLBbPwngCf3Obyyy3AsilHH32mWfxVbP4fmoZ69jxbXSvOxFUWgMM
M8e8RoqYuNMQPW6z5oNGDuVuQfFwDmQS5CuYC6Me2u5c6JvgDegOwHRm0imnn194
-----END PRIVATE KEY-----`,
  },
  {
    name: 'secp384r1-pub-explicit-no-seed',
    pem: `-----BEGIN PUBLIC KEY-----
MIIBtTCCAU0GByqGSM49AgEwggFAAgEBMDwGByqGSM49AQECMQD/////////////
/////////////////////////////v////8AAAAAAAAAAP////8wZAQw////////
//////////////////////////////////7/////AAAAAAAAAAD////8BDCzMS+n
4j7n5JiOBWvj+C0ZGB2cbv6BQRIDFAiPUBOHWsZWOY2KLtGdKoXI7dPsKu8EYQSq
h8oivosFN46xxx7zIK10bh07Younm5hZ90HgglQqOFUC8l2/VSlsOlReOHJ2Crc2
F95KliYsb12emL+Sktwp+PQdvSiaFHzp2jETtfC4wApgsc4dfoGdekMdfJDqDl8C
MQD////////////////////////////////HY02B9Dct31gaDbJIsKd67OwZaszF
KXMCAQEDYgAE/1AnYnoYBP8Fs+qvYzmZL7qQQnszUNKBNWG5Hctfh4rmDafRhYPX
J4aOOD99lGCpacn0NUxHbPpz1wylfJQYe65CUSiUjO82WPQ7HWdW2L03dsheBJz9
3s8GVZNOGyFU
-----END PUBLIC KEY-----`,
  },
  {
    name: 'secp384r1-pub-explicit-seed',
    pem: `-----BEGIN PUBLIC KEY-----
MIIBzDCCAWQGByqGSM49AgEwggFXAgEBMDwGByqGSM49AQECMQD/////////////
/////////////////////////////v////8AAAAAAAAAAP////8wewQw////////
//////////////////////////////////7/////AAAAAAAAAAD////8BDCzMS+n
4j7n5JiOBWvj+C0ZGB2cbv6BQRIDFAiPUBOHWsZWOY2KLtGdKoXI7dPsKu8DFQCj
NZJqoxmieh0AiWpnc6SCes2scwRhBKqHyiK+iwU3jrHHHvMgrXRuHTtii6ebmFn3
QeCCVCo4VQLyXb9VKWw6VF44cnYKtzYX3kqWJixvXZ6Yv5KS3Cn49B29KJoUfOna
MRO18LjACmCxzh1+gZ16Qx18kOoOXwIxAP//////////////////////////////
/8djTYH0Ny3fWBoNskiwp3rs7BlqzMUpcwIBAQNiAATxKkf19dGjLnEsFs/CeAJ/
c5vLLLcCyKUcffaZZ/FVs/h+ahnr2PFtdK87EVRaAwwzx7xGipi40xA9brPmg0YO
5W5B8XAOZBLkK5gLox7a7lzom+AN6A7AdGbSKaefX3g=
-----END PUBLIC KEY-----`,
  },
  {
    name: 'secp521r1-explicit-no-seed',
    pem: `-----BEGIN PRIVATE KEY-----
MIICmQIBADCCAbkGByqGSM49AgEwggGsAgEBME0GByqGSM49AQECQgH/////////
////////////////////////////////////////////////////////////////
/////////////zCBiARCAf//////////////////////////////////////////
///////////////////////////////////////////8BEIAUZU+uWGOHJofkpoh
oLaFQO6i2nJbmbMV87i0iZGO8QnhVhk5Uex+k3sWUsC9O7G/BzVz34g9LDTx70Uf
1GtQPwAEgYUEAMaFjga3BATpzZ4+y2YjlbRCnGSBOQU/tSH4KK9ga009uqFLXnfv
51ko/h3BJ6L/qN4zSLPBhWpCm/l+fjHC5b1mARg5KWp4mjvABFyKX7QsfRvZmPVE
SVebRGgXr70XJz5mLJfucple9CZAxVC5AT+tB2E1PHCGonLCQIi+lHaf0WZQAkIB
///////////////////////////////////////////6UYaHg78vlmt/zAFI9wml
0Du1ybiJnEeuu2+3HpE4ZAkCAQEEgdYwgdMCAQEEQgB01EEtlzfayNIInreIvwX6
FP/ZH/YBJNkoAfTtc16+cO1rZVWxkMHHriD8N2Qwqd9QnJME6jWHzb1Effu9xQB3
8KGBiQOBhgAEASibXsZQxJ6voXpafbPdqVmssNfA5rJda8h67iRgIYmRKnkYdlIX
QPa48PjqsbdnKW6YmV/QODmeAIyhGVUtDyBwATc4pptFdB9ABipSL0VWGuuSC8ir
YE0maGnNclJqnbZEaoOkQgYw2QSYdRvnabUQrycxq5JRgbD5KzxIUOSmAZHs
-----END PRIVATE KEY-----`,
  },
  {
    name: 'secp521r1-explicit-seed',
    pem: `-----BEGIN PRIVATE KEY-----
MIICsAIBADCCAdAGByqGSM49AgEwggHDAgEBME0GByqGSM49AQECQgH/////////
////////////////////////////////////////////////////////////////
/////////////zCBnwRCAf//////////////////////////////////////////
///////////////////////////////////////////8BEIAUZU+uWGOHJofkpoh
oLaFQO6i2nJbmbMV87i0iZGO8QnhVhk5Uex+k3sWUsC9O7G/BzVz34g9LDTx70Uf
1GtQPwADFQDQnogAKRy4U5bMZxc5MoSqoNpkugSBhQQAxoWOBrcEBOnNnj7LZiOV
tEKcZIE5BT+1Ifgor2BrTT26oUted+/nWSj+HcEnov+o3jNIs8GFakKb+X5+McLl
vWYBGDkpaniaO8AEXIpftCx9G9mY9URJV5tEaBevvRcnPmYsl+5ymV70JkDFULkB
P60HYTU8cIaicsJAiL6Udp/RZlACQgH/////////////////////////////////
//////////pRhoeDvy+Wa3/MAUj3CaXQO7XJuImcR667b7cekThkCQIBAQSB1jCB
0wIBAQRCAeIS+AXTSxkEd9Oll6ax8sC5uZIYJBwGzoXyoPMLllSo3ZWhmTPykqDb
Ouymh4B6d7v5zH04x+hA90g+DC0MgXfAoYGJA4GGAAQAU1BgMCzHl5BFxXJ9G7Kc
ZlcKv8qBWoZkadGVcdxSXGu7VH0OckMcRfmgi3gjJvu+yxTSjAlLWwmM5JA5Bbn1
TSoAja1sdGJE97x4Eeh+teTZ4xELYAXfA+jWrSCnOpmmAJoj4QPPpT4FPVcoGXjU
LJSq5XunFjM2uo3WL491wq3Y8LY=
-----END PRIVATE KEY-----`,
  },
  {
    name: 'secp521r1-pub-explicit-no-seed',
    pem: `-----BEGIN PUBLIC KEY-----
MIICRjCCAbkGByqGSM49AgEwggGsAgEBME0GByqGSM49AQECQgH/////////////
////////////////////////////////////////////////////////////////
/////////zCBiARCAf//////////////////////////////////////////////
///////////////////////////////////////8BEIAUZU+uWGOHJofkpohoLaF
QO6i2nJbmbMV87i0iZGO8QnhVhk5Uex+k3sWUsC9O7G/BzVz34g9LDTx70Uf1GtQ
PwAEgYUEAMaFjga3BATpzZ4+y2YjlbRCnGSBOQU/tSH4KK9ga009uqFLXnfv51ko
/h3BJ6L/qN4zSLPBhWpCm/l+fjHC5b1mARg5KWp4mjvABFyKX7QsfRvZmPVESVeb
RGgXr70XJz5mLJfucple9CZAxVC5AT+tB2E1PHCGonLCQIi+lHaf0WZQAkIB////
///////////////////////////////////////6UYaHg78vlmt/zAFI9wml0Du1
ybiJnEeuu2+3HpE4ZAkCAQEDgYYABAEom17GUMSer6F6Wn2z3alZrLDXwOayXWvI
eu4kYCGJkSp5GHZSF0D2uPD46rG3ZylumJlf0Dg5ngCMoRlVLQ8gcAE3OKabRXQf
QAYqUi9FVhrrkgvIq2BNJmhpzXJSap22RGqDpEIGMNkEmHUb52m1EK8nMauSUYGw
+Ss8SFDkpgGR7A==
-----END PUBLIC KEY-----`,
  },
  {
    name: 'secp521r1-pub-explicit-seed',
    pem: `-----BEGIN PUBLIC KEY-----
MIICXTCCAdAGByqGSM49AgEwggHDAgEBME0GByqGSM49AQECQgH/////////////
////////////////////////////////////////////////////////////////
/////////zCBnwRCAf//////////////////////////////////////////////
///////////////////////////////////////8BEIAUZU+uWGOHJofkpohoLaF
QO6i2nJbmbMV87i0iZGO8QnhVhk5Uex+k3sWUsC9O7G/BzVz34g9LDTx70Uf1GtQ
PwADFQDQnogAKRy4U5bMZxc5MoSqoNpkugSBhQQAxoWOBrcEBOnNnj7LZiOVtEKc
ZIE5BT+1Ifgor2BrTT26oUted+/nWSj+HcEnov+o3jNIs8GFakKb+X5+McLlvWYB
GDkpaniaO8AEXIpftCx9G9mY9URJV5tEaBevvRcnPmYsl+5ymV70JkDFULkBP60H
YTU8cIaicsJAiL6Udp/RZlACQgH/////////////////////////////////////
//////pRhoeDvy+Wa3/MAUj3CaXQO7XJuImcR667b7cekThkCQIBAQOBhgAEAFNQ
YDAsx5eQRcVyfRuynGZXCr/KgVqGZGnRlXHcUlxru1R9DnJDHEX5oIt4Iyb7vssU
0owJS1sJjOSQOQW59U0qAI2tbHRiRPe8eBHofrXk2eMRC2AF3wPo1q0gpzqZpgCa
I+EDz6U+BT1XKBl41CyUquV7pxYzNrqN1i+PdcKt2PC2
-----END PUBLIC KEY-----`,
  },
  {
    name: 'sect163k1-spki',
    pem: `-----BEGIN PUBLIC KEY-----
MEAwEAYHKoZIzj0CAQYFK4EEAAEDLAAEAxGAaICwgq0YOcgiIg1qIBU/tmU3AS4t
jG+YV5KpVbVoZrj9Z+fb24Pg
-----END PUBLIC KEY-----`,
    decoded: {
      algorithm: {
        info: { TAG: 'EC', data: { TAG: 'namedCurve', data: '1.3.132.0.1' } },
      },
      publicKey: new Uint8Array([
        4, 3, 17, 128, 104, 128, 176, 130, 173, 24, 57, 200, 34, 34, 13, 106, 32, 21, 63, 182, 101,
        55, 1, 46, 45, 140, 111, 152, 87, 146, 169, 85, 181, 104, 102, 184, 253, 103, 231, 219, 219,
        131, 224,
      ]),
    },
  },
  {
    name: 'sect163r2-spki',
    pem: `-----BEGIN PUBLIC KEY-----
MEAwEAYHKoZIzj0CAQYFK4EEAA8DLAAEAkMQD2BC7lzGH0cqllPPPtNl1kqRBXhT
JmwDP66hW6PMFl3ldz4ZlvkK
-----END PUBLIC KEY-----`,
    decoded: {
      algorithm: {
        info: { TAG: 'EC', data: { TAG: 'namedCurve', data: '1.3.132.0.15' } },
      },
      publicKey: new Uint8Array([
        4, 2, 67, 16, 15, 96, 66, 238, 92, 198, 31, 71, 42, 150, 83, 207, 62, 211, 101, 214, 74,
        145, 5, 120, 83, 38, 108, 3, 63, 174, 161, 91, 163, 204, 22, 93, 229, 119, 62, 25, 150, 249,
        10,
      ]),
    },
  },
  {
    name: 'sect233k1-spki.pem',
    pem: `-----BEGIN PUBLIC KEY-----
MFIwEAYHKoZIzj0CAQYFK4EEABoDPgAEAbCYgpNMrLez2VEmv+xSGQLxtnWoDDvK
4oh4XfQEAPETU2P//4hH7hiDxo1jfe104nG45sbYJQke8+OK
-----END PUBLIC KEY-----`,
    decoded: {
      algorithm: {
        info: { TAG: 'EC', data: { TAG: 'namedCurve', data: '1.3.132.0.26' } },
      },
      publicKey: new Uint8Array([
        4, 1, 176, 152, 130, 147, 76, 172, 183, 179, 217, 81, 38, 191, 236, 82, 25, 2, 241, 182,
        117, 168, 12, 59, 202, 226, 136, 120, 93, 244, 4, 0, 241, 19, 83, 99, 255, 255, 136, 71,
        238, 24, 131, 198, 141, 99, 125, 237, 116, 226, 113, 184, 230, 198, 216, 37, 9, 30, 243,
        227, 138,
      ]),
    },
  },
  {
    name: 'sect233r1-spki',
    pem: `-----BEGIN PUBLIC KEY-----
MFIwEAYHKoZIzj0CAQYFK4EEABsDPgAEAVfRTJ18T67P5XD5HXs9dv7NuO+FQwNl
9/COeQIjAWjajHoGNjsris/W25ZMPcq240TdudpXmHC5gFiV
-----END PUBLIC KEY-----`,
    decoded: {
      algorithm: {
        info: { TAG: 'EC', data: { TAG: 'namedCurve', data: '1.3.132.0.27' } },
      },
      publicKey: new Uint8Array([
        4, 1, 87, 209, 76, 157, 124, 79, 174, 207, 229, 112, 249, 29, 123, 61, 118, 254, 205, 184,
        239, 133, 67, 3, 101, 247, 240, 142, 121, 2, 35, 1, 104, 218, 140, 122, 6, 54, 59, 43, 138,
        207, 214, 219, 150, 76, 61, 202, 182, 227, 68, 221, 185, 218, 87, 152, 112, 185, 128, 88,
        149,
      ]),
    },
  },
  {
    name: 'bad-encryption-oid.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoYYYYYYYYYYYYYMA4ECHK0M0+QuEL9AgIBIgSCAoDRq+KRY+0XP0tO
lwBTzViiXSXoyNnKAZKt5r5K/fGNntv22g/1s/ZNCetrqsJDC5eMUPPacz06jFq/
Ipsep4/OgjQ9UAOzXNrWEoNyrHnWDo7usgD3CW0mKyqER4+wG0ZdVMbt3N+CJHGB
85jzRmQTfkdx1rSWeSx+XyswHn8ER4+hQ+omKWMVm7AFkjjmP/KmhUnLT98J8rhU
ArQoFPHz/6HVkypFccNaPPNg6IA4aS2A+TU9vJYOaXSVfFB2yf99hfYYzC+ukmuU
5Lun0cysK5s/5uSwDueUmDQKspnaNyiaMGDxvw8hilJc7vg0fGObfnbIpizhxJwq
gKBfR7Zt0Hv8OYi1He4MehfMGdbHskztF+yQ40LplBGXQrvAqpU4zShga1BoQ98T
0ekbBmqj7hg47VFsppXR7DKhx7G7rpMmdKbFhAZVCjae7rRGpUtD52cpFdPhMyAX
huhMkoczwUW8B/rM4272lkHo6Br0yk/TQfTEGkvryflNVu6lniPTV151WV5U1M3o
3G3a44eDyt7Ln+WSOpWtbPQMTrpKhur6WXgJvrpa/m02oOGdvOlDsoOCgavgQMWg
7xKKL7620pHl7p7f/8tlE8q6vLXVvyNtAOgt/JAr2rgvrHaZSzDE0DwgCjBXEm+7
cVMVNkHod7bLQefVanVtWqPzbmr8f7gKeuGwWSG9oew/lN2hxcLEPJHAQlnLgx3P
0GdGjK9NvwA0EP2gYIeE4+UtSder7xQ7bVh25VB20R4TTIIs4aXXCVOoQPagnzaT
6JLgl8FrvdfjHwIvmSOO1YMNmILBq000Q8WDqyErBDs4hsvtO6VQ4LeqJj6gClX3
qeJNaJFu
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'bad-oid-dsa-key.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIIBTAIBADCCASwGByXXXXXXXXEwggEfAoGBAKoJMMwUWCUiHK/6KKwolBlqJ4M9
5ewhJweRaJQgd3Si57I4sNNvGySZosJYUIPrAUMpJEGNhn+qIS3RBx1NzrJ4J5St
OTzAik1K2n9o1ug5pfzTS05ALYLLioy0D+wxkRv5vTYLA0yqy0xelHmSVzyekAmc
Gw8FlAyr5dLeSaFnAhUArcDoabNvCsATpoH99NSJnWmCBFECgYEAjGtFia+lOk0Q
SL/DRtHzhsp1UhzPct2qJRKGiA7hMgH/SIkLv8M9ebrK7HHnp3hQe9XxpmQi45QV
vgPnEUG6Mk9bkxMZKRgsiKn6QGKDYGbOvnS1xmkMfRARBsJAq369VOTjMB/Qhs5q
2ski+ycTorCIfLoTubxozlz/8kHNMkYEFwIVAKU1qOHQ2Rvq/IvuHZsqOo3jMRID
-----END PRIVATE KEY-----`,
    shouldFail: true,
  },

  {
    name: 'ec-consistent-curve.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgYirTZSx+5O8Y6tlG
cka6W6btJiocdrdolfcukSoTEk+gCgYIKoZIzj0DAQehRANCAAQkvPNu7Pa1GcsW
U4v7ptNfqCJVq8Cxzo0MUVPQgwJ3aJtNM1QMOQUayCrRwfklg+D/rFSUwEUqtZh7
fJDiFqz3
-----END PRIVATE KEY-----`,
    decoded: {
      version: 0n,
      algorithm: {
        info: {
          TAG: 'EC',
          data: { TAG: 'namedCurve', data: '1.2.840.10045.3.1.7' },
        },
      },
      privateKey: {
        TAG: 'struct',
        data: {
          version: 1n,
          privateKey: new Uint8Array([
            98, 42, 211, 101, 44, 126, 228, 239, 24, 234, 217, 70, 114, 70, 186, 91, 166, 237, 38,
            42, 28, 118, 183, 104, 149, 247, 46, 145, 42, 19, 18, 79,
          ]),
          parameters: { TAG: 'namedCurve', data: '1.2.840.10045.3.1.7' },
          publicKey: new Uint8Array([
            4, 36, 188, 243, 110, 236, 246, 181, 25, 203, 22, 83, 139, 251, 166, 211, 95, 168, 34,
            85, 171, 192, 177, 206, 141, 12, 81, 83, 208, 131, 2, 119, 104, 155, 77, 51, 84, 12, 57,
            5, 26, 200, 42, 209, 193, 249, 37, 131, 224, 255, 172, 84, 148, 192, 69, 42, 181, 152,
            123, 124, 144, 226, 22, 172, 247,
          ]),
        },
      },
      attributes: undefined,
      publicKey: undefined,
    },
  },

  {
    name: 'ec-inconsistent-curve.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIGQAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHYwdAIBAQQgYirTZSx+5O8Y6tlG
cka6W6btJiocdrdolfcukSoTEk+gBwYFK4EEACKhRANCAAQkvPNu7Pa1GcsWU4v7
ptNfqCJVq8Cxzo0MUVPQgwJ3aJtNM1QMOQUayCrRwfklg+D/rFSUwEUqtZh7fJDi
Fqz3
-----END PRIVATE KEY-----`,
    decoded: {
      version: 0n,
      algorithm: {
        info: {
          TAG: 'EC',
          data: { TAG: 'namedCurve', data: '1.2.840.10045.3.1.7' },
        },
      },
      privateKey: {
        TAG: 'struct',
        data: {
          version: 1n,
          privateKey: new Uint8Array([
            98, 42, 211, 101, 44, 126, 228, 239, 24, 234, 217, 70, 114, 70, 186, 91, 166, 237, 38,
            42, 28, 118, 183, 104, 149, 247, 46, 145, 42, 19, 18, 79,
          ]),
          parameters: { TAG: 'namedCurve', data: '1.3.132.0.34' },
          publicKey: new Uint8Array([
            4, 36, 188, 243, 110, 236, 246, 181, 25, 203, 22, 83, 139, 251, 166, 211, 95, 168, 34,
            85, 171, 192, 177, 206, 141, 12, 81, 83, 208, 131, 2, 119, 104, 155, 77, 51, 84, 12, 57,
            5, 26, 200, 42, 209, 193, 249, 37, 131, 224, 255, 172, 84, 148, 192, 69, 42, 181, 152,
            123, 124, 144, 226, 22, 172, 247,
          ]),
        },
      },
      attributes: undefined,
      publicKey: undefined,
    },
  },

  {
    name: 'ec-inconsistent-curve2.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIGQAgEAMBAGByqGSM49AgEGBSuBBAAiBHkwdwIBAQQgYirTZSx+5O8Y6tlGcka6
W6btJiocdrdolfcukSoTEk+gCgYIKoZIzj0DAQehRANCAAQkvPNu7Pa1GcsWU4v7
ptNfqCJVq8Cxzo0MUVPQgwJ3aJtNM1QMOQUayCrRwfklg+D/rFSUwEUqtZh7fJDi
Fqz3
-----END PRIVATE KEY-----`,
    decoded: {
      version: 0n,
      algorithm: {
        info: { TAG: 'EC', data: { TAG: 'namedCurve', data: '1.3.132.0.34' } },
      },
      privateKey: {
        TAG: 'struct',
        data: {
          version: 1n,
          privateKey: new Uint8Array([
            98, 42, 211, 101, 44, 126, 228, 239, 24, 234, 217, 70, 114, 70, 186, 91, 166, 237, 38,
            42, 28, 118, 183, 104, 149, 247, 46, 145, 42, 19, 18, 79,
          ]),
          parameters: { TAG: 'namedCurve', data: '1.2.840.10045.3.1.7' },
          publicKey: new Uint8Array([
            4, 36, 188, 243, 110, 236, 246, 181, 25, 203, 22, 83, 139, 251, 166, 211, 95, 168, 34,
            85, 171, 192, 177, 206, 141, 12, 81, 83, 208, 131, 2, 119, 104, 155, 77, 51, 84, 12, 57,
            5, 26, 200, 42, 209, 193, 249, 37, 131, 224, 255, 172, 84, 148, 192, 69, 42, 181, 152,
            123, 124, 144, 226, 22, 172, 247,
          ]),
        },
      },
      attributes: undefined,
      publicKey: undefined,
    },
  },

  {
    name: 'ec-invalid-private-scalar.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIGUAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHoweAIBAQRz////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////AA==
-----END PRIVATE KEY-----`,
    decoded: {
      version: 0n,
      algorithm: {
        info: {
          TAG: 'EC',
          data: { TAG: 'namedCurve', data: '1.2.840.10045.3.1.7' },
        },
      },
      privateKey: {
        TAG: 'struct',
        data: {
          version: 1n,
          privateKey: new Uint8Array([
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0,
          ]),
          parameters: undefined,
          publicKey: undefined,
        },
      },
      attributes: undefined,
      publicKey: undefined,
    },
  },

  {
    name: 'ec-invalid-version.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBEQQgYirTZSx+5O8Y6tlG
cka6W6btJiocdrdolfcukSoTEk+gCgYIKoZIzj0DAQehRANCAAQkvPNu7Pa1GcsW
U4v7ptNfqCJVq8Cxzo0MUVPQgwJ3aJtNM1QMOQUayCrRwfklg+D/rFSUwEUqtZh7
fJDiFqz3
-----END PRIVATE KEY-----`,
    decoded: {
      version: 0n,
      algorithm: {
        info: {
          TAG: 'EC',
          data: { TAG: 'namedCurve', data: '1.2.840.10045.3.1.7' },
        },
      },
      privateKey: {
        TAG: 'struct',
        data: {
          version: 17n,
          privateKey: new Uint8Array([
            98, 42, 211, 101, 44, 126, 228, 239, 24, 234, 217, 70, 114, 70, 186, 91, 166, 237, 38,
            42, 28, 118, 183, 104, 149, 247, 46, 145, 42, 19, 18, 79,
          ]),
          parameters: { TAG: 'namedCurve', data: '1.2.840.10045.3.1.7' },
          publicKey: new Uint8Array([
            4, 36, 188, 243, 110, 236, 246, 181, 25, 203, 22, 83, 139, 251, 166, 211, 95, 168, 34,
            85, 171, 192, 177, 206, 141, 12, 81, 83, 208, 131, 2, 119, 104, 155, 77, 51, 84, 12, 57,
            5, 26, 200, 42, 209, 193, 249, 37, 131, 224, 255, 172, 84, 148, 192, 69, 42, 181, 152,
            123, 124, 144, 226, 22, 172, 247,
          ]),
        },
      },
      attributes: undefined,
      publicKey: undefined,
    },
  },

  {
    name: 'ec_oid_not_in_reg_private_2.pkcs8.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIHaAgEAMIG0BgcqhkjOPQIBMIGoAgEBMCIGByqGSM49AQECFw4aFhluYAAAAAC8
d5mvQORfIMKCpz8jMDIEFwpp6Dq3yY/XFMent6k68ZVN0TLoYuwCBBcF27ytezfC
QvUCsMLrgpmKMPgl7QmshQQvBAegDesPaZK6sjNlLdtcbzMdfScPlwnsBYlNHz+Z
VzzAHH+at1C946ahHkssjp4CFw4aFhluYAAAAAC8fxYY2GexW7hkdEGPAgEBBB4w
HAIBAQQXBJJ/aqWyXJt0gblb7AjQYjSqWnHULjY=
-----END PRIVATE KEY-----`,
    decoded: {
      version: 0n,
      algorithm: {
        info: {
          TAG: 'EC',
          data: {
            TAG: 'specifiedCurve',
            data: {
              version: 1n,
              fieldId: {
                info: {
                  TAG: 'primeField',
                  data: 1350693651377962542635138423054063834983335105718075171n,
                },
              },
              curve: {
                a: new Uint8Array([
                  10, 105, 232, 58, 183, 201, 143, 215, 20, 199, 167, 183, 169, 58, 241, 149, 77,
                  209, 50, 232, 98, 236, 2,
                ]),
                b: new Uint8Array([
                  5, 219, 188, 173, 123, 55, 194, 66, 245, 2, 176, 194, 235, 130, 153, 138, 48, 248,
                  37, 237, 9, 172, 133,
                ]),
                seed: undefined,
              },
              base: new Uint8Array([
                4, 7, 160, 13, 235, 15, 105, 146, 186, 178, 51, 101, 45, 219, 92, 111, 51, 29, 125,
                39, 15, 151, 9, 236, 5, 137, 77, 31, 63, 153, 87, 60, 192, 28, 127, 154, 183, 80,
                189, 227, 166, 161, 30, 75, 44, 142, 158,
              ]),
              order: 1350693651377962542635138425370864348766711642133381519n,
              cofactor: 1n,
              hash: undefined,
              rest: Uint8Array.of(),
            },
          },
        },
      },
      privateKey: {
        TAG: 'struct',
        data: {
          version: 1n,
          privateKey: new Uint8Array([
            4, 146, 127, 106, 165, 178, 92, 155, 116, 129, 185, 91, 236, 8, 208, 98, 52, 170, 90,
            113, 212, 46, 54,
          ]),
          parameters: undefined,
          publicKey: undefined,
        },
      },
      attributes: undefined,
      publicKey: undefined,
    },
  },

  {
    name: 'ec_private_key.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYirTZSx+5O8Y6tlG
cka6W6btJiocdrdolfcukSoTEk+hRANCAAQkvPNu7Pa1GcsWU4v7ptNfqCJVq8Cx
zo0MUVPQgwJ3aJtNM1QMOQUayCrRwfklg+D/rFSUwEUqtZh7fJDiFqz3
-----END PRIVATE KEY-----`,
    decoded: {
      version: 0n,
      algorithm: { info: { TAG: 'EC', data: { TAG: 'namedCurve', data: '1.2.840.10045.3.1.7' } } },
      privateKey: {
        TAG: 'struct',
        data: {
          version: 1n,
          privateKey: new Uint8Array([
            98, 42, 211, 101, 44, 126, 228, 239, 24, 234, 217, 70, 114, 70, 186, 91, 166, 237, 38,
            42, 28, 118, 183, 104, 149, 247, 46, 145, 42, 19, 18, 79,
          ]),
          parameters: undefined,
          publicKey: new Uint8Array([
            4, 36, 188, 243, 110, 236, 246, 181, 25, 203, 22, 83, 139, 251, 166, 211, 95, 168, 34,
            85, 171, 192, 177, 206, 141, 12, 81, 83, 208, 131, 2, 119, 104, 155, 77, 51, 84, 12, 57,
            5, 26, 200, 42, 209, 193, 249, 37, 131, 224, 255, 172, 84, 148, 192, 69, 42, 181, 152,
            123, 124, 144, 226, 22, 172, 247,
          ]),
        },
      },
      attributes: undefined,
      publicKey: undefined,
    },
  },
  {
    name: 'ec_private_key_encrypted.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHeMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAhpLrlPneL1ZgICCAAw
HQYJYIZIAWUDBAECBBB5hfsFcYGp9fULEhMlHHnoBIGQL7hbr9fwZAMZcKl0C9+A
fPaIVSEmPtJabSF9SxgjaVbpJsU81L/UopIExtVAuolwI+OYAyKWLr/g8Dh+tC4K
yzF+nzpx0/na5g0xkCOk4TAJUCL/3eQVZ2y3qdB3/xjR/q1Sxly48wTMM+AdV46p
cWNJtnQ4VRkyGVxGHRfQSUQHK6pkFEGB+aUXkNHAdBED
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'ecc_private_with_rfc5915_ext.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfKBDxcP88OEfI4v6
k8JFIQquWzap0+HHXE7N6DzuvamhRANCAAR7M3jrGYZXDSqbcSAmd0wO+V8Wx49D
jqUVeAbI24rCMk3+mUTTFwwQn0p9nTdf56a1VNl4P9XUM5cbJnqwh5Yl
-----END PRIVATE KEY-----`,
    decoded: {
      version: 0n,
      algorithm: {
        info: {
          TAG: 'EC',
          data: { TAG: 'namedCurve', data: '1.2.840.10045.3.1.7' },
        },
      },
      privateKey: {
        TAG: 'struct',
        data: {
          version: 1n,
          privateKey: new Uint8Array([
            124, 160, 67, 197, 195, 252, 240, 225, 31, 35, 139, 250, 147, 194, 69, 33, 10, 174, 91,
            54, 169, 211, 225, 199, 92, 78, 205, 232, 60, 238, 189, 169,
          ]),
          parameters: undefined,
          publicKey: new Uint8Array([
            4, 123, 51, 120, 235, 25, 134, 87, 13, 42, 155, 113, 32, 38, 119, 76, 14, 249, 95, 22,
            199, 143, 67, 142, 165, 21, 120, 6, 200, 219, 138, 194, 50, 77, 254, 153, 68, 211, 23,
            12, 16, 159, 74, 125, 157, 55, 95, 231, 166, 181, 84, 217, 120, 63, 213, 212, 51, 151,
            27, 38, 122, 176, 135, 150, 37,
          ]),
        },
      },
      attributes: undefined,
      publicKey: undefined,
    },
  },

  {
    name: 'ed25519-scrypt.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGTME8GCSqGSIb3DQEFDTBCMCEGCSsGAQQB2kcECzAUBAjmIR4jSK1p4AICQAAC
AQgCAQEwHQYJYIZIAWUDBAEqBBCb0KYlHyJU+f1ZY4h8J88BBEDMYrp3PA9JX6s2
aOT8782wjnig7hXgoVAT9iq+CNqnQgZe6zZtbmyYzDsOfmm9yGHIiv648D26Hixt
mdBtFzYM
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'enc-ec-sha1-128-rc4.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGrMBwGCiqGSIb3DQEMAQEwDgQIprjt98myskECAggABIGKdJJyNgMqiLL0EWI3
ZVto6g9msWT2ovpySiGxZyoUDfFrqfBuHY4IqwL/PYr9La1u/F/VuP5DRLf47YWp
iwfxc6sYedBU85f0c14Ha2Yc6hUEakCbQEzCqEg8RmJ2oDETbTO9STlMyk9ou8XV
7hdRkBqKNj3RIdgf01Aj5t8YmYsrKTx9VUDBpij0
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'enc-rsa-3des.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI9fSurwMcOA4CAggA
MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECKALBF48zvQnBIIEyKDIy72IMJoZ
4q7LsG0dCSa8oGI/CtAnC9YqRlDj+paWoGKDUkzxnMloUbJkpQlTEYRHXp0xKtdP
IcCjWFqWeQjsaJUlwILNLiliVpbyW/0PLmNQmRSfvLhlZ77rRk08DyLU0mcW2zRX
DuKHuxGhdlmte7EKsNf8czch9hDXqrCLqxlzr86K0pwT40W1r32TgQdX68edluoj
acggWuEzeTTKy1BKkVtlCq63dflgRfSo0as+dYX38wxzC6O6hxKpax277ijoJZHc
QsXxi/zREa+gtVOq9D6Vz5E+MmmIIAzVrXsFe1Uj4wYb3XUSO6WnJ9GlrixqWeu3
9lkOZOEKyyDgIY+twn06kyZBspKnXvQMMPjeiSSeaqI9LA0qpvRsxuWCxyTJ2YZI
s+xab8j5g5RKOmrt1bGtLl66tcrGNP9jYC5pjMNl6fz3c8+oxC0Bun4q+yOA9QzG
4GaiA834x+9wtsEBSjlMB5AMwYH+1ODo6Q+VUAWH1qBvCm/gQT2mvSgcrz6bcGJI
gimfzl/IbqVuVkWl7yFqNN/renE47pvy34Dbymb0FBK/5Gb1FImno3CcAkCuaEJ1
sWdx2Ej0Ezit8v1iJN2q29xlD7MrxB0uPvklUPRlD9RVcDJ15GwBPA8ugN/Fjj50
2BiMJ2/uqBoEnAjMyStINArS5PWL6gthIXenVJ4w0wegBciCsGo4G7UFQ0z/w2Je
7NJ8TjwKdTYJdAfgO5Rr8u6j0ybn72T/+QJfjugNLufRx4sakvPZR90/AFb2YX+L
kgCVS3ySOfom9p5JcxdnI8omelBIi1Qa9xwPKMPaV6oYkqBVjmcDDZocC6qN15PD
jCrgGryV3Fsn5OLYTB+EQDLNqmo+qd1O0pNY2THwD/DGGlx6VhmeQnWdt534g5lo
clQOmLXEeUWIb2u5PanakqNpY5mBQcOJ88/RS+oGAjTGU0e3I1zLb6EN/Ftndjv1
sfEh+HMwHxIWxdnJb6z6m73XJr4z30VGN8e+f1lC8c9SJ9aTQ/9vH3bsaXLW6GFY
DBisBg2/+vMwRSG9PkYrp1p6rGAhwbaofnZE5zApT7PFEX2RVNPU7lgXn84ycRHw
gZ89Mpa9zShL4T1PS8BrKwS7AH/se7ofKW/s8Z9SgngTWj0Efd4hZmn/EenVHBWf
kjAkvKIgGE8FJF1QlmU5dHDFhRiUGXIaB1rYAcwwuwB06fxRqEL3pU6jkHSru3ry
sYaY/cfpd5D5PT+FlxkzAPH1iiC3knXpcotWpJ2iQshsw9ifwg/vVJB0n20+Rxeu
XTgwiT+X5mJNAQUCj6aExWUg+D5gPnJPwFmzAWBGKWrvwI+vI6zIv4MJywzU+Ei8
1lU5rezPovAbGSTwUBPDydhORua0P8tVT8KPMmPJhza6IORTPpzdEOCXCOH17CWg
VWKjYvEul8CdNh4O3CJDU4lN8yn6RXCBPK4NKDea17GCIEBgnOnpFny+jdfNT+Ce
9aNh8ah61vbPag9EM2okmBlbnpkhUO+x8K8prZHZE7qRgUbmn1cJwIP6pNN/263q
S2uKZMnoaT65BaQh9wpgSvWmDup3/lGG/C2+m0k087QBVHMSfpTK9WcZ94BbzoeR
S9rWCU2k/woEUOv3hssY5w==
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'enc-rsa-pkcs8.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEDMA4ECGr8xKw0AqdcAgIBIgSCAoDgVKEZ5FzA3Jaj
TuMSyoIhra3tHiMZvDO/OQiYkMVxh5CyeWjjDxqBXrE2I/gdrfDfv18ObL7bNWGB
QL77W0Z52nZaeU6jN5B+q5U3P4vxeYFE9LrSLl4v2EFqRyMT8jrzKthUYvISnrP/
HuvzGCO1Tlg2Dvt+ql3DLLyYsEEfCe+0h3UIeiuTYFshFXx4vVDlplmTxHysc1rU
90J5niRYprVeXF+9erPT30s1wd0gd27J5LUu8fi+g3TisWbjVyMd8NEQhSeXdT40
Pal8l26ZSMg6B7VwYfpjJHB8+itzRvlmCTuUbnlCgd8fiLmjn2/s5JEdPomiUFYG
xjw1RkBEe5/oM1nzlRXr3q1vpLMU7Q2umbMfVKp+yF4fGgR2iGE/T6/KvT+mPioD
S5cnbRBYnLWlBktdeXEtVJeH5pvCW4KIK7qJxaA49re8+f0LMf0IE37s/WIJXic4
1/MO9NLjcOEiynChK613It7is9DCPhDWTTSaDtRbrbl+KH3f8DBiqiWJVmwVug0D
TSeLmxCicCmyxqFIJBxaTsDYjgd3Z19vftpyeTIrqAMvK+PWJHFkwgILuEUGapgW
qYSL2EQKeepZzw57IAwW6MG7iPaP0CN3a0enyZ4PkYWtsKUbF6ZpiX0qFJAd5D9i
7kCvN9huAvC1CCT4zghpQXvQ1W5EnQDHQ/efCFngB5HlKQr4jrfUmjg2yOcAK/ih
aLHjPX5x9+W9fDVXRNMhYTs96JzVVcEg9WP6ID/PuVt/pxbBexFCNXjBokNTbpnI
BFK1DuvIqhzMcstsaaFCAXTeaWdcNZI3fDkaxM8ArgxTCr7nDGLKuaHcS1+XtzuA
kJNTLBIv
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'enc-unknown-algorithm.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFIDBSBgkqhkiG9w0BBQ0wRTApBgkqhkiG9w0BBQwwHAQI9fSurwMcOA4CAggA
MAwGCCqGSIb3DQIJBQAwGAYMKoZIhvcNAwcXgkEDBAigCwRePM70JwSCBMigyMu9
iDCaGeKuy7BtHQkmvKBiPwrQJwvWKkZQ4/qWlqBig1JM8ZzJaFGyZKUJUxGER16d
MSrXTyHAo1halnkI7GiVJcCCzS4pYlaW8lv9Dy5jUJkUn7y4ZWe+60ZNPA8i1NJn
Fts0Vw7ih7sRoXZZrXuxCrDX/HM3IfYQ16qwi6sZc6/OitKcE+NFta99k4EHV+vH
nZbqI2nIIFrhM3k0ystQSpFbZQqut3X5YEX0qNGrPnWF9/MMcwujuocSqWsdu+4o
6CWR3ELF8Yv80RGvoLVTqvQ+lc+RPjJpiCAM1a17BXtVI+MGG911EjulpyfRpa4s
alnrt/ZZDmThCssg4CGPrcJ9OpMmQbKSp170DDD43okknmqiPSwNKqb0bMblgsck
ydmGSLPsWm/I+YOUSjpq7dWxrS5eurXKxjT/Y2AuaYzDZen893PPqMQtAbp+Kvsj
gPUMxuBmogPN+MfvcLbBAUo5TAeQDMGB/tTg6OkPlVAFh9agbwpv4EE9pr0oHK8+
m3BiSIIpn85fyG6lblZFpe8hajTf63pxOO6b8t+A28pm9BQSv+Rm9RSJp6NwnAJA
rmhCdbFncdhI9BM4rfL9YiTdqtvcZQ+zK8QdLj75JVD0ZQ/UVXAydeRsATwPLoDf
xY4+dNgYjCdv7qgaBJwIzMkrSDQK0uT1i+oLYSF3p1SeMNMHoAXIgrBqOBu1BUNM
/8NiXuzSfE48CnU2CXQH4DuUa/Luo9Mm5+9k//kCX47oDS7n0ceLGpLz2UfdPwBW
9mF/i5IAlUt8kjn6JvaeSXMXZyPKJnpQSItUGvccDyjD2leqGJKgVY5nAw2aHAuq
jdeTw4wq4Bq8ldxbJ+Ti2EwfhEAyzapqPqndTtKTWNkx8A/wxhpcelYZnkJ1nbed
+IOZaHJUDpi1xHlFiG9ruT2p2pKjaWOZgUHDifPP0UvqBgI0xlNHtyNcy2+hDfxb
Z3Y79bHxIfhzMB8SFsXZyW+s+pu91ya+M99FRjfHvn9ZQvHPUifWk0P/bx927Gly
1uhhWAwYrAYNv/rzMEUhvT5GK6daeqxgIcG2qH52ROcwKU+zxRF9kVTT1O5YF5/O
MnER8IGfPTKWvc0oS+E9T0vAaysEuwB/7Hu6Hylv7PGfUoJ4E1o9BH3eIWZp/xHp
1RwVn5IwJLyiIBhPBSRdUJZlOXRwxYUYlBlyGgda2AHMMLsAdOn8UahC96VOo5B0
q7t68rGGmP3H6XeQ+T0/hZcZMwDx9Yogt5J16XKLVqSdokLIbMPYn8IP71SQdJ9t
PkcXrl04MIk/l+ZiTQEFAo+mhMVlIPg+YD5yT8BZswFgRilq78CPryOsyL+DCcsM
1PhIvNZVOa3sz6LwGxkk8FATw8nYTkbmtD/LVU/CjzJjyYc2uiDkUz6c3RDglwjh
9ewloFVio2LxLpfAnTYeDtwiQ1OJTfMp+kVwgTyuDSg3mtexgiBAYJzp6RZ8vo3X
zU/gnvWjYfGoetb2z2oPRDNqJJgZW56ZIVDvsfCvKa2R2RO6kYFG5p9XCcCD+qTT
f9ut6ktrimTJ6Gk+uQWkIfcKYEr1pg7qd/5RhvwtvptJNPO0AVRzEn6UyvVnGfeA
W86HkUva1glNpP8KBFDr94bLGOc=
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'enc-unknown-kdf.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFIDBSBgkqhkiG9w0BBQ0wRTAtBg0qhkiG9w0BBQyCQYJBMBwECPX0rq8DHDgO
AgIIADAMBggqhkiG9w0CCQUAMBQGCCqGSIb3DQMHBAigCwRePM70JwSCBMigyMu9
iDCaGeKuy7BtHQkmvKBiPwrQJwvWKkZQ4/qWlqBig1JM8ZzJaFGyZKUJUxGER16d
MSrXTyHAo1halnkI7GiVJcCCzS4pYlaW8lv9Dy5jUJkUn7y4ZWe+60ZNPA8i1NJn
Fts0Vw7ih7sRoXZZrXuxCrDX/HM3IfYQ16qwi6sZc6/OitKcE+NFta99k4EHV+vH
nZbqI2nIIFrhM3k0ystQSpFbZQqut3X5YEX0qNGrPnWF9/MMcwujuocSqWsdu+4o
6CWR3ELF8Yv80RGvoLVTqvQ+lc+RPjJpiCAM1a17BXtVI+MGG911EjulpyfRpa4s
alnrt/ZZDmThCssg4CGPrcJ9OpMmQbKSp170DDD43okknmqiPSwNKqb0bMblgsck
ydmGSLPsWm/I+YOUSjpq7dWxrS5eurXKxjT/Y2AuaYzDZen893PPqMQtAbp+Kvsj
gPUMxuBmogPN+MfvcLbBAUo5TAeQDMGB/tTg6OkPlVAFh9agbwpv4EE9pr0oHK8+
m3BiSIIpn85fyG6lblZFpe8hajTf63pxOO6b8t+A28pm9BQSv+Rm9RSJp6NwnAJA
rmhCdbFncdhI9BM4rfL9YiTdqtvcZQ+zK8QdLj75JVD0ZQ/UVXAydeRsATwPLoDf
xY4+dNgYjCdv7qgaBJwIzMkrSDQK0uT1i+oLYSF3p1SeMNMHoAXIgrBqOBu1BUNM
/8NiXuzSfE48CnU2CXQH4DuUa/Luo9Mm5+9k//kCX47oDS7n0ceLGpLz2UfdPwBW
9mF/i5IAlUt8kjn6JvaeSXMXZyPKJnpQSItUGvccDyjD2leqGJKgVY5nAw2aHAuq
jdeTw4wq4Bq8ldxbJ+Ti2EwfhEAyzapqPqndTtKTWNkx8A/wxhpcelYZnkJ1nbed
+IOZaHJUDpi1xHlFiG9ruT2p2pKjaWOZgUHDifPP0UvqBgI0xlNHtyNcy2+hDfxb
Z3Y79bHxIfhzMB8SFsXZyW+s+pu91ya+M99FRjfHvn9ZQvHPUifWk0P/bx927Gly
1uhhWAwYrAYNv/rzMEUhvT5GK6daeqxgIcG2qH52ROcwKU+zxRF9kVTT1O5YF5/O
MnER8IGfPTKWvc0oS+E9T0vAaysEuwB/7Hu6Hylv7PGfUoJ4E1o9BH3eIWZp/xHp
1RwVn5IwJLyiIBhPBSRdUJZlOXRwxYUYlBlyGgda2AHMMLsAdOn8UahC96VOo5B0
q7t68rGGmP3H6XeQ+T0/hZcZMwDx9Yogt5J16XKLVqSdokLIbMPYn8IP71SQdJ9t
PkcXrl04MIk/l+ZiTQEFAo+mhMVlIPg+YD5yT8BZswFgRilq78CPryOsyL+DCcsM
1PhIvNZVOa3sz6LwGxkk8FATw8nYTkbmtD/LVU/CjzJjyYc2uiDkUz6c3RDglwjh
9ewloFVio2LxLpfAnTYeDtwiQ1OJTfMp+kVwgTyuDSg3mtexgiBAYJzp6RZ8vo3X
zU/gnvWjYfGoetb2z2oPRDNqJJgZW56ZIVDvsfCvKa2R2RO6kYFG5p9XCcCD+qTT
f9ut6ktrimTJ6Gk+uQWkIfcKYEr1pg7qd/5RhvwtvptJNPO0AVRzEn6UyvVnGfeA
W86HkUva1glNpP8KBFDr94bLGOc=
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'enc-unknown-pbkdf2-prf.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFIDBSBgkqhkiG9w0BBQ0wRTAtBgkqhkiG9w0BBQwwIAQI9fSurwMcOA4CAggA
MBAGDCqGSIb3DQIJgVWCQQUAMBQGCCqGSIb3DQMHBAigCwRePM70JwSCBMigyMu9
iDCaGeKuy7BtHQkmvKBiPwrQJwvWKkZQ4/qWlqBig1JM8ZzJaFGyZKUJUxGER16d
MSrXTyHAo1halnkI7GiVJcCCzS4pYlaW8lv9Dy5jUJkUn7y4ZWe+60ZNPA8i1NJn
Fts0Vw7ih7sRoXZZrXuxCrDX/HM3IfYQ16qwi6sZc6/OitKcE+NFta99k4EHV+vH
nZbqI2nIIFrhM3k0ystQSpFbZQqut3X5YEX0qNGrPnWF9/MMcwujuocSqWsdu+4o
6CWR3ELF8Yv80RGvoLVTqvQ+lc+RPjJpiCAM1a17BXtVI+MGG911EjulpyfRpa4s
alnrt/ZZDmThCssg4CGPrcJ9OpMmQbKSp170DDD43okknmqiPSwNKqb0bMblgsck
ydmGSLPsWm/I+YOUSjpq7dWxrS5eurXKxjT/Y2AuaYzDZen893PPqMQtAbp+Kvsj
gPUMxuBmogPN+MfvcLbBAUo5TAeQDMGB/tTg6OkPlVAFh9agbwpv4EE9pr0oHK8+
m3BiSIIpn85fyG6lblZFpe8hajTf63pxOO6b8t+A28pm9BQSv+Rm9RSJp6NwnAJA
rmhCdbFncdhI9BM4rfL9YiTdqtvcZQ+zK8QdLj75JVD0ZQ/UVXAydeRsATwPLoDf
xY4+dNgYjCdv7qgaBJwIzMkrSDQK0uT1i+oLYSF3p1SeMNMHoAXIgrBqOBu1BUNM
/8NiXuzSfE48CnU2CXQH4DuUa/Luo9Mm5+9k//kCX47oDS7n0ceLGpLz2UfdPwBW
9mF/i5IAlUt8kjn6JvaeSXMXZyPKJnpQSItUGvccDyjD2leqGJKgVY5nAw2aHAuq
jdeTw4wq4Bq8ldxbJ+Ti2EwfhEAyzapqPqndTtKTWNkx8A/wxhpcelYZnkJ1nbed
+IOZaHJUDpi1xHlFiG9ruT2p2pKjaWOZgUHDifPP0UvqBgI0xlNHtyNcy2+hDfxb
Z3Y79bHxIfhzMB8SFsXZyW+s+pu91ya+M99FRjfHvn9ZQvHPUifWk0P/bx927Gly
1uhhWAwYrAYNv/rzMEUhvT5GK6daeqxgIcG2qH52ROcwKU+zxRF9kVTT1O5YF5/O
MnER8IGfPTKWvc0oS+E9T0vAaysEuwB/7Hu6Hylv7PGfUoJ4E1o9BH3eIWZp/xHp
1RwVn5IwJLyiIBhPBSRdUJZlOXRwxYUYlBlyGgda2AHMMLsAdOn8UahC96VOo5B0
q7t68rGGmP3H6XeQ+T0/hZcZMwDx9Yogt5J16XKLVqSdokLIbMPYn8IP71SQdJ9t
PkcXrl04MIk/l+ZiTQEFAo+mhMVlIPg+YD5yT8BZswFgRilq78CPryOsyL+DCcsM
1PhIvNZVOa3sz6LwGxkk8FATw8nYTkbmtD/LVU/CjzJjyYc2uiDkUz6c3RDglwjh
9ewloFVio2LxLpfAnTYeDtwiQ1OJTfMp+kVwgTyuDSg3mtexgiBAYJzp6RZ8vo3X
zU/gnvWjYfGoetb2z2oPRDNqJJgZW56ZIVDvsfCvKa2R2RO6kYFG5p9XCcCD+qTT
f9ut6ktrimTJ6Gk+uQWkIfcKYEr1pg7qd/5RhvwtvptJNPO0AVRzEn6UyvVnGfeA
W86HkUva1glNpP8KBFDr94bLGOc=
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'enc2-rsa-pkcs8.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIzREWMrgTFhACAggA
MB0GCWCGSAFlAwQBAgQQMviW+mesguQLBlrtpFQePwSCAoDRkK53Am4vn1P8RgJ3
cZd0GYMSCSA5bai+0+O2H8t4lTYt/zKwXAugXJ4k59ALvqJJSlciRKY+kKlqK50q
e4Zeum59VDj4EhLMw/Of08W+omM7qAIOdujnBwn0rxTZNeq6cKj1iCLshP293AQB
fpQBZlq0F2LMro+n4b+r0eiZvE6Osyr/Da3EcG74d4CWTAwt7eaZ/MZWfekeRoEE
wPm2ne3hTPfppSx4fPQ5wnMOWk9grc70D/sHZx7AvYiWmN1xJf9w8e+1Tv+MdQJG
6fd1qyMi15dib77vE5PB3+LVdZqDu/VYaxqaxhzVnmiqUUDWuNFQEeMOuOUULXRW
Qe93ZKDq2g8cpj+tv62+qfTU+9UUN4EUlGjFKTAK6OioA3gbtWLNhy9Gv6DqSAHx
k0SsxuMswBrwRYYTJWZVHrcWmGaMk1F3KinYSjpr9cy/2vtTp0/afMp/+2054gu8
xt7ruppF+znEWVF5AO9mv29Vz3Nxc8MRf44Ml5Z7v/B9bwqRFW5EtJkFKfllQtS5
hbqUy+JT+91h/ZAQmiuHrEtJ4biiBSAgHMGqBoElcl118lPubS1bYb9KDJgiKT6q
IzKEKKWlJTgcVyXTA1EsMDmEKMmH5X8R1alqm4vdrsTyHYOsXDCI8OvNA65pDt55
t3FU8hQfVTeW+TpHlmXI1BGWHh/k9AVGprLC4ZNm9rssKK6z3baQofIrC4yERg7t
5gJeT2tHe0UXMwOl2HtVIp7xTuKmeKaJPIMcp6bIBSg/Z+8JRcoPChE/dFTRowmO
6pUJDwI3seNp8WN+L2rmW6fTcQpstWzh/ewVxBtq+IzXu8+/570eIeaTu+nEZ2pf
81eu
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'nodompar_private.pkcs8.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIIB0QIBADCCAYcGByqGSM49AgEwggF6AgEBMEUGByqGSM49AQECOgthcsnViAAA
AAAAAAAAAAAAAAAAAAAAAAAAAEdshQ7mkmMLkJZUVU4Ol915g3uKHPNUo9AwD+x4
7PkweAQ6Cjd97ea1IzM9NseOmw6qO/SM6TBB9tT8NAFNCPaDOAdJje7dQpAQHFhm
6N+1iUhdEzV7nnjC1/vp/gQ6CprPjIumF3d+JIUJvLRxfU2zRiAr+eNSzVYzcx3Z
KlG3Kk3Ds9F8gj/Mj72k2gjyXeqJBGCHNCWVpwR1BAgVI9A9TxLNAoed6kv2pPOn
3ybtiI8QxbIjWhJ0w4ai8hgwDe5u0heEEWRTO83JA/B6CW+fv07pW6wJihEfKW9Y
MP5cNbPjRNXfOiJWmF9k++bQ7cxMYdGL72gd05nfPQGUxaQxXgEuAkXs6lY2W6qe
i+H3AjoLYXLJ1YgAAAAAAAAAAAAAAAAAAAAAAAAAAABHbIeQSOXYXqco7S6hwduS
xOT5ZSNk/c26d1X6bDYvAgEBBEEwPwIBAQQ6CQZ+cOjNmFKHK7JoXGdAPByb7XfI
kTIoUEiQxOiDRUH9pUqf0lpcCHhjtTb9hQZ1RGYrjqsccdL6ng==
-----END PRIVATE KEY-----`,
    decoded: {
      version: 0n,
      algorithm: {
        info: {
          TAG: 'EC',
          data: {
            TAG: 'specifiedCurve',
            data: {
              version: 1n,
              fieldId: {
                info: {
                  TAG: 'primeField',
                  data: 2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809n,
                },
              },
              curve: {
                a: new Uint8Array([
                  10, 55, 125, 237, 230, 181, 35, 51, 61, 54, 199, 142, 155, 14, 170, 59, 244, 140,
                  233, 48, 65, 246, 212, 252, 52, 1, 77, 8, 246, 131, 56, 7, 73, 141, 238, 221, 66,
                  144, 16, 28, 88, 102, 232, 223, 181, 137, 72, 93, 19, 53, 123, 158, 120, 194, 215,
                  251, 233, 254,
                ]),
                b: new Uint8Array([
                  10, 154, 207, 140, 139, 166, 23, 119, 126, 36, 133, 9, 188, 180, 113, 125, 77,
                  179, 70, 32, 43, 249, 227, 82, 205, 86, 51, 115, 29, 217, 42, 81, 183, 42, 77,
                  195, 179, 209, 124, 130, 63, 204, 143, 189, 164, 218, 8, 242, 93, 234, 137, 4, 96,
                  135, 52, 37, 149, 167,
                ]),
                seed: undefined,
              },
              base: new Uint8Array([
                4, 8, 21, 35, 208, 61, 79, 18, 205, 2, 135, 157, 234, 75, 246, 164, 243, 167, 223,
                38, 237, 136, 143, 16, 197, 178, 35, 90, 18, 116, 195, 134, 162, 242, 24, 48, 13,
                238, 110, 210, 23, 132, 17, 100, 83, 59, 205, 201, 3, 240, 122, 9, 111, 159, 191,
                78, 233, 91, 172, 9, 138, 17, 31, 41, 111, 88, 48, 254, 92, 53, 179, 227, 68, 213,
                223, 58, 34, 86, 152, 95, 100, 251, 230, 208, 237, 204, 76, 97, 209, 139, 239, 104,
                29, 211, 153, 223, 61, 1, 148, 197, 164, 49, 94, 1, 46, 2, 69, 236, 234, 86, 54, 91,
                170, 158, 139, 225, 247,
              ]),
              order:
                2117607112719756483104013348936480976596328609518055062007450442679169560544635038870047971694050522140428624585740792203722206722065708591n,
              cofactor: 1n,
              hash: undefined,
              rest: Uint8Array.of(),
            },
          },
        },
      },
      privateKey: {
        TAG: 'struct',
        data: {
          version: 1n,
          privateKey: new Uint8Array([
            9, 6, 126, 112, 232, 205, 152, 82, 135, 43, 178, 104, 92, 103, 64, 60, 28, 155, 237,
            119, 200, 145, 50, 40, 80, 72, 144, 196, 232, 131, 69, 65, 253, 165, 74, 159, 210, 90,
            92, 8, 120, 99, 181, 54, 253, 133, 6, 117, 68, 102, 43, 142, 171, 28, 113, 210, 250,
            158,
          ]),
          parameters: undefined,
          publicKey: undefined,
        },
      },
      attributes: undefined,
      publicKey: undefined,
    },
  },

  {
    name: 'pkcs12_s2k_pem-X_9607.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEDMA4ECL9rjpW835n6AgIIAASCAoAjs558e/tWq5ho
X3uYORURfasssTfqyZoSaTmEWJGbW7T+QK+ebZ8CyMVbR1ORD3rd6r7cWLsX3Ju0
hGncPFVpwCtwApZKnWCunj4KcsRuWdm1vAauRV2CDkykMzNlsJzAw+BPFKi2B7HL
xn5JymtqrGZF6zRDWW1x1WD3HYlq4FoNuSmNFu4fV0EyalIopIyNmZAY40lQ/FTM
LkTsnH2brIYHV1Bnzd/lXpXLli29OE/4WsPBTvhJLZGbJXp8ExwGuxfDnTFCPS9G
9uOjaBgerl2zjsdPNXBfn8hDNrs7MDqR9aC6rZR0yE1maEPv0YnnzDGRYZl6+j2K
FfWDMGET6SSimYCcZJwr0/xZAdw5e323k1xniCNVfbQhCQ09Cl6XoDI8IK23O8g+
R9o8gCikl98fJlpKjHaKfnscSE0hMzOjyAbYjFxWAlzjffzR5o+P6955dhREpCWy
kL2EOL2VmYfzGG4J62p9U88MXhCLuFOuHL/wtGzXwGnyqZyeZ5p2fYloGPEMVsX7
zHupLUpVZFe4kOBGI/IPWbc2iQTvzDtx9Jvxo5vWmyEwL8C7P/f9+zsIaXiM3Onz
F5qwQfCojesuelGPAfXJxJRLaHicva90+IyRFBSMKxgt3EdHER/R7huA//jzzQp9
eItmiv2UwAafeiPEDT74n6yBCTMPc++cJsMWL0SNIX4jYep55bgzbgGB8t/nQ0Ho
7/1KF1sAO3klAkrcTwL4pX2vLMa//W/H/AAQ2FL/Q+CAP7K5X2rlZxdkFlMuL3Dr
I0UqiStjznkoOeWjj6YT3jOvKGLWHPXqxTkW9Ln4fDvAoI9eq6UWHjf7gLYXxe/q
tTpNnYdy
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'pkcs12_s2k_pem-X_9671.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEDMA4ECA7RZbNgWxdHAgIIAASCAoAq1B5klspIe7B/
R1pKifO1/29OsAQn9blIbaJ9fg62ivA3QGL0uApZ6eNFz6JEZyiRITJYhgLaWwov
mqKT9NiQ6iiemgxWLSSdvEXVOMRZB17F9PncpEiIBpnrisdD7h9MpS63LuJdEtiK
jpPwFwV3orFJceurq/R3ql2aKYc9MZSzkKd71QImgHYWv+IPCctl40/PZV08yKMn
RCMVFb/YYUrzaWSerroyjz4Kr8V0nEyKpk4YLv7o7WPGn4x8X30z0BRCA9CBwzHY
JMxu1FhOGXr6nx1XeaoCOt9JV8GWb+VzkATABPzFG915ULz0ma1petQyb18QyBsl
K9NZETrGzDYiNxkjqILhY6IRneB97C4kCH55qhXHFk5fjiWndpQ6+BFKqlCqm6Up
d1EF3uuKN+vY6xQbGCgFE4FHL46nb2YaoaqhPp4dj4qnRSllgBvmZbGTd243lAbT
J4dh/gzRwQYdIwbvcNVi9GGSOy/fezAwwXu3ZD9BqqqoCQJajrILuovbcPThy71k
H5EaegQ1rB+0/sn91JUb6w4pwN/54gzZGaz2F0/2xB9u57+PIMC9R8dU7uW/xWfA
WN7YTzPDNfevbx/LIa6VR5gsiRqCnthSsGvWFquRatMv1JrDfFUywFU9zk9W+iA2
rtNpXV140+/BDfHbYYrUIaklJsNP0FRXKpPw9wPHHmbOjHfFK+o8PrtOp3HUsCJm
2VpQtbNl66+rPLZLsbXhuJ5eY/BpRvrj6rDFPs19OAvYyrIsuQY8IdbZyGSKsq4u
UBsHZgPBh718EtWFFrsTNxMlRKoh5MwUSqkLXeDduAFG4N7nhQpDHQ5/KRPrYOMK
ixB1lLUK
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'pkcs12_s2k_pem-X_9925.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEDMA4ECDnNkmSKl37mAgIIAASCAoAwttidBRLnnjti
b5BEsc8cO2vzImhJbYCrVDjkTpmS6IYD4FsC8KFDdQJrEYIptrwXn4uDWDUu6bxB
pb02Pj70gZiWBDU+ki1kIbsNc67rNpJfUlIU+po3UovSmrazqcHoW2IftvZo9hDF
FWVjc0D2fSWeaNwS7dimWxoLy1udof6n0c8UxvfnOgfSLg3qwWzc0+iMrbkvRFX5
9+vDCnetQ7ythKldnC5xQxShxaNF4O26D0VXdR9VYbQLslSHAzQi2wJ7Hh1fi62J
VUHvRNOcwhSadwNfQEtvIWoi6LfsUadvvhFAAbeSfQpSfD4iXgfcr3U2WIvjtOcL
cZg9HqRhGzgEuC7FLoov1re7xq3uifw+04qu8i9/fk7hUrldZCrCSKTc6GqsiY8x
JGOcNUgklzy6kbgIWp9O2C5Bxp1WmfnbNSMM9Z9UFTdbEa4Kz7SYd+1a8j1OWlq1
93AcEpD0+fpKuEs+S1RF7RRAs/Ais0VcOmgye0TLvKkhockxl4KT0SbOTeKnmxJ3
RSnPcHUb62EZuhHqpoHi+zjHH56sVy3RhcYsDKIh1Xh7JPGTysflOIno7ABK8Tu7
IcnAOCoBVTjXC5eSSeC3irvZSILHC1tBG8r1C1aSLFmxpOTCqRUwhtbw/FSqEngl
5pvwTz4gquyjCPjIAWlCscAbeqpBxNsmnJ0AGlaesd9/uxrWUScTnAIc+NUB9o8w
i+zXbOqhbKxWGfrQAo+qZtAchQ6EGxXuIxnSRlAEZtsrJt6/FXJaOIb5MvcXA/sQ
O2p1r9W2OZM8Jco2ftALygUFPDiIuELaiTQ8HE1heUZWy+M9gXV6wCGhIVtRYyCg
SSQ62gp7
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'pkcs12_s2k_pem-X_9926.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEDMA4ECE8YpbN3dz05AgIIAASCAoC1wuyUEZs/FSTB
llt567hf1L+wiQ24L49ZvLutwb0nkilLHNXUo95mpLfzjnr7ZBbsIPV0RTdxjIKX
IdRD9SzMxeMUJ82obmgE2tTeOi7PqONX838Lmj3ocUR+aFBFTR1V7G2gMpQEapPX
gjv3kgwG5DCSj15NG8ybT4ZHWURyc/57dn0JWXc9/XUbm/+lvwwsuu9YvQ5Z76jE
ufiS8OCHNo1nPMCsUIw6herr2OfC5pj2H1/6bC7L/NPZJ7OM/IQoQOcNxiwx8rBS
zChy7dvPbJYmd5N+066mZiyFGxQwjPziXmqJztnB34P0Yp9dsiE1M+fo//f+QkFW
3HDMJmb+becnUAjiWuQCT/YqNjC4iHn35Jb2COPsV5KPsSaQ+6IaN4vWx7ifvHGD
KzkFcKQ1Be1EiOnUGBqhW4r7ASFKMtqGlTRBoc8PVMdFIpadejGW31Csz5gussa2
OcOLO8kULsT9QsuWyayG4SuTweClCaJ/nGJ/nDnocVPbucqRQBFn9ZRQ0VSLhDLe
B3HYRx3sJ9U+Xay9cgR09hMQ2ZaR/NxYlRshKEt+iiYOS42eMyMXVKfBwQwxl9Lf
ESBz7GF2nOT5VSSgJlAf3nbfhUABgq2zzoybKlFVpnq49Z79rB4b+lkP8jIhV5GA
/aUXssvs68FsqbG+T1nBnFWkJL49XENOrwDApzGllVbtaruoIe9t+qBF6rXVSjWQ
ZATZaSD3gOaM4Oyv+lso4GuONXkaXQRdpBmPLChdLMkcopQOQZtlKU2+rzi4Nm4X
lAAsR4sXmIGYJ3EgQrTDE+igMNr8o2qHIh81zqP7nWtkfTEfFqud6zoGK5aiZ4ma
0StcnRpp
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'pkcs12_s2k_pem-X_9927.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEDMA4ECC6HV5s66uQrAgIIAASCAoAgQMR7E4EoMQSq
kFslHKebFtjtrCqEPW5lADxpJg8+FNOT6GCCnu8yslrmMa4l/MIs8jfkoKhP9O8W
IjQpwG5IGr0ZyfxYPZFTatrQ7+MvtMoQMBTxVt20oW4kT3tTF4KDf0BUsB9JCoET
DehlFSPTjDJav8fGbdEMhfbY6+6iBodnW7a3Ibil+7CQGeRIGDO7mEu5rBbI1fJb
tGEHkCd6Gvv20r/EIi6Fol9Fwc5eKxgFioIuZo3Tmqrr/9g09sv+qwkzoNFmpqby
AqCbgOOsckc3AXm4xZ7AX7zNSFXbfhiX1EyVvhwfJ6jiqHr32K8o5I4Cb/lzpB+q
WPMU/rF5bsTj0+/eySx8zkIUF/Jst9E+XtzlTFtMVzNpFYfzg3E+0qnT8KJtZJGr
Azz9aCNidjkjRVHUubrZ5qbjrv1eAYnFkgyw+UTyIJBeec6CRH5zob22ZMb5jKFz
d9reY1LZ38cQIoKThPdv9vKRVEd1I7T5MKv656+QegfqA7Kefwa0uK+TvvqBLTd1
mxgtkDvrID3PLZK9tVsOLMJcY1PFCNHB6T2EghMVEmMnROVLCqIN+MeraLhHemUe
rf6HFlOcYPV+5V8gI/DM2Fw/V+YgCzv380Z6HouZ4K1nwvEf53renettQmKxK/Fd
X74KqRSs6FtANdVUziGkrvNfssRjjLHxD08VfLAcpijRfNslxDIXQIASWqn3TPFY
uDs32vonOVrj2Zy8fIBRmENmGe5b/jnp055NLo6MWCFR3hmmeFBuXk6o1K6io3Le
oaeWr7BJFIxXZZ8zNUlBLGZinY50oM09DFOpiAUTQtkm8NuAThLcqmWvbw8LWmL4
ed6Pdtej
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'pkcs12_s2k_pem-X_9928.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEDMA4ECC1OO648bIPcAgIIAASCAoDiQoIuNdleFu2V
I8MUwZ6I0Om2+2yHSrk7Jxd0mbIYnT832dVsWg53SkcBYggnN1bByej0qtf2pdBx
EKsOjU9T6XmOZyFjJKX6MK6syqFYI4Y67OzdiDS8FVMCYX8NhhsYlE1aqvBjvnjq
tgpR0pJg8uJ3FmUu1N/6ayjGtI9JbZFt+BkqbZxIfdaZhlXx1vgU2MtuxDultlJu
rjvzcCGG0z0GcVEmXUwVccvLqwnL6UnYkVAmhCzj4UvxYsMt6Dp8FPSQi54jmZKx
4LAOGGGZcKoOTJYCrUkW2RAV/GzbhT1kOJR2/Pw21Yw/WkVKyNE8LHghu6xr3pXy
MPmCn0fE751Vjefb6NOYIjvmMexaZVzBCZ6kuxEQBlGDi15lohnpZLcFilS7l5IY
nWZJ9qPX19O0RG9NgQ4xpxoPBdrxqP5HuieKgvAZ7RXDXeKlW/4z/Fo2dBjPc0YJ
Y5QPOK+i2Zux9VtMbxkXBeO7KsiosNQthFP+HitlIs72MHUsBZucEnZ9ny0S+blG
gKYK9xuuAPGscqaI6fcicFOc0ZmphMn5YP6D0nN9esqo44s9JX7SyLRPuHW+dH0/
Bdg9LikS8ROBs3Yuy9ksGHMbMsguum3mOwiY8f2NXQwVs3b7VfkIDMbYAjMGcriE
CsW1Z4EzQP2qCFVJYz6S3xSsKtgg3QeWKCtvGRJDbzCnaQGCrrHzyBlGZzr5NJkr
4x7MxbWppvVTMySJ+Y3V2DR+Q1nW5P7qzWaY9tE9d8unCym5C/S2CE/39jQ9zMmL
56qvh2swSrCEKInhQyqV+4msSYVElrQY0DGbg/N6TsKvN37zCqKKBIxhyb/5b2Kv
QvN7D2Ch
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'pkcs12_s2k_pem-X_9929.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEDMA4ECAPza28YOfuMAgIIAASCAoBg+t7v3fo4gOZX
+/IY3xln+5pVj6LKXXgHWydK25TLD3oxlrecVKmnWWZuQIcPVosItr+KfwRMfkY5
BKUQZyu02ZO/u9cXe3XsmZLpiWAXVCaRfHhXkZ24PxQGIVikDc8KyHEAhX/P+e9m
jJEneTP+hdQvZmJGKKqOG95HkqlnH5KJhM8W7BjDgPBeCjaBcc9AzCWX+WdY4Nbn
LONjhe0nXPuVArLayru67q62LUf/NZOM6j7gbYe0ki94rXddabpOIGBhf9qP1pWc
m5RBntEOtlbuosUYhlOpse91SBM2nHnOzM1fIxX6J9p/AlctvtB+Zoqx4OEwbRxT
hNpCUo+3rwmAAOz6CntGHpmfFKrzc0r37aoSjnlQJKTxDRJHN43+eqbdtNpaQfDH
0pS4o84oO3/CgnJ45Bx3HJXNlg3YvKhHWav8wtHX085URoc8h/OJ3PiKBi7+5AYR
CLAaJjtTC0ReaOXjyGfhzzuux7UDl+MW0D69vaz2t7HSR2tQ4tYnA4fciqirSKdL
wFgewXRNxNkQKo149YfE2weMGXW/DYGRXl8RMUwGsur10nesfUBZfLPYW014rDm+
QjGa2bcYJMUnAtUz1ctaQNV8T4HM3SwXABSbuczDGM4FpFCd51tjJDh8vxdmZpGJ
KEhWsvXcrlzBpVyW5CX/TixVYzautBdOM2cN+yniLjHAkHBWCF39LoAQatbHNFSq
FpADIpMiGFyGMxf029s2JgdNvkgR2aUL0ed2hGP9kKyLio+RNF5HD7mbbBM4d06P
t79aRgHvQAOeHJPfz9LleOoRUpg1gb8jmLDtKkWe+JGtsEDCPeb0HTvlL4ttGrZ4
LoIPCVbz
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'pkcs12_s2k_pem-X_9930.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEDMA4ECM70GUHLNxJ7AgIIAASCAoBSzIR/pzL/Kz0k
QYJburqvHquGAa/xevMdelJdqAKPfqMuaOOhbZUkpp1Yf/jswyrzImgOnkb2stO8
hsa3gTZLk3j1LA5JXb89Pm+dqv1gXWJco7dnq8JJEhTt7Mr6rm/P1uV9UBXlgv+E
2F+b8GBDikMw38zqRGtg3GPjFaZKcL7tqwRm390t57cWSbqLLaNmRIxcf5TARHEs
TZEU+BHF2JoFE7rXPdUJAJwsw35C5JS4DXwEUBVoEeI3jXl3yDOqu20uekbrndL5
seACup8mQp5nHUBNk6RMg7/8/hqeRU9IFyCstvFqjtvbPvJLEML8jSyd+XoZU1tm
VpnU7KcN3bSN/BK4QzChGr5sD/2rteceBIJjDsHR7FjHJQIKlTxMok3taM84knnw
QcO0T0vbsmUqbs1MltGcUgm3p6Jp/NyeHZGfDqu4TEZcHE+mrNVVReRHL3O55UpC
AyZeJDu9nQKe62Y6oGcOUOuZkoodfh9M1V44f9guOv5b+2VIFgUIZTOVHLkmb3Nx
r6rUn2++N02II7zkvR1aHILZw/JnqHQC5bpK6qlTNUN3kNy5DHg4iAHGuKUxksK0
qziPL/VYfos0/81O4mNI3yo3D2WA6usgy+MZyDY0u4uAbcz4irE1ACHj3cgBHx2j
RemyLdgPX+kPXr5wKHKk4U93nIgZXbshuuG5CrwtJqXslx6dG6FYChaUJsc/kCga
JFkHnOZk3tMxxyVBaBKUnyFxbxFBORgYGGAEKJ4RYT0ge8sSkVo4NNsNjLw74+d6
zlt7NLEhDn+IuaocYejf4Do5W+jIfkpZXF/w6DRHyJ3l2CHV/c9AN/lltTQYIg4Y
twhxefdG
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'pkcs12_s2k_pem-X_9931.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEDMA4ECO6DyRswVDToAgIIAASCAoB3xqmr0evfZnxk
Gq/DsbmwGVpO1BQnv+50u8+roflrmHp+TdX/gkPdXDQCqqpK/2J/oaGMCtKEiO8R
/pxSKcCX3+7leF01FF4z3rEcTVRej0mR6IAzk5QZR4Y0jXzay7Quj2zFJQTASdRy
6o9HQt5YuDyMFY30yjungmg6sYLBLZ2XypCJYH3eUQx9BjwsbGqVnXRQ6oezL5tD
K+tRH41OK2pzFqhnpRvbfPtNDmUnMLUnahGBubRzNQgHE0iNGIYpOawpVabj15H2
4lQ9KBREaqLqiV/VMPFYcRd8tBjE2pRs3yhJ9bjl73gdh6qVvcXIqBBQcRtNbpQ/
WKFzVz5dMCEzS+LhMT2m0GtTYqn8IqRuDgF7P8+347k4wKvrA2XgwP0bvh+IBb4e
nMQuJaKsnMZZPgAPqfIqWsn3cw27iEb5ros+My4KMlMbKBvH2HTXx5YkYJfbRLJ1
oe0mUxshTSOJeOjsfkStsP7QCSIvVb76t2Jo6HKIXEylXFAzj39lea6aysx6KX4c
aC/9XDlhqs0GGcJE3ILbiePTWWiASWjS08ggQasMZsT4VYUaIl3ti1N1cK9xwkaD
BE12JvWEtPd7MtGouPGijXycAtNgPw17vWg/3O11vTKDAHse90dOOpqYpXFN9Cfi
wa72WOkxFEZDuzV/dmjXX1WN82MoXs7pkHLvTgCmdydQ0ZJABYZj1+ZnF5eR6zLo
LAJnV3gOY0DGLORuoifEWMRlzDyYQOBN9smK9xKDtA6CHUuB9jRHKBevQrFy4+Ed
trCmsp9qXPzGvmJOA1YEgnZZPvXjAB7TCv2VrftKgebzbQE2mOoF1YcT1PIB7dFL
AopQ9gdD
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'pkcs12_s2k_pem-X_9932.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEDMA4ECEKkETmhIXPkAgIIAASCAoBzNPQiMSQC6RSk
5Lk5cAbP1r//rE3IA0MNVy2ZwM4UZAQYHCxHkMpParGXwKt3/me064RXRwKOg9UT
nGx5/2A/AI2061A5M0KPVFE41IWQWoVGaiCaAzUDSF2Y+SL9yuLVqEES0gDQgUv5
uVnGyrbSo7sT8MSdvBuzdgmVluiaEVQhfwWJ9f8Q+ebQ1WVkeftzCe9yp1PLj8Yl
VCQ6X5qXqsApJ34Y62wXGqNbEvBkRyKbSqfqMI837tAVdMCdbsEE7wavzxGW6F9h
+igbPZO1NSzY0FZX1eQYqKZxfbkQmyDPLFT2S7BVv2wmihnC/SeZTcOoM+QoWG9j
XNLr1oqbeNxOnELmOXSrOekzbI7GhUcphYEIOBG/4B7ZP3cZ6TEw1EygXUan09XZ
Uz/CFbBTfX1uXHkMSzWwowXpx12vjH78KrRn69WBMGn/YjUheDLjwCDhJQK2CRDH
LbNBvZ7ezy1qHX90jrIdQnQzAoynu1OCfbd+84U2VifAszTcRvPMdiLlJh9MeyFY
8xDmmeNYGTVuDvAuzTlqbGablgQJu80VZ8CgQSW/0x7+oPozichza9tOd19aMDJ4
f8REy/9DAn1jRq/Cy/JFQoTpq3NtcWf9+NPHCwOMjaL63m6fIPXw6s9hnq8WMVIS
mtf5Jkvf402+8jhw1IqTVJasOMTRn62KsRt9a4JcWtorECA42wZGXjge3K9HYk4T
IVXq39VmeRP/9WveDwjkIThMl+0v5fl6Baaz/krXOIRfL6LV3RpkqPF4j/wneXgZ
7cMySs/FL96y6A+yJv281IQadYCqj7nPy92IYESQIcYjA8nd8hvsOxpnaMjXZjui
UWl07o3w
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'private.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIIBjQIBADCCAU0GByqGSM49AgEwggFAAgEBMDwGByqGSM49AQECMQCMuR6Cozht
KA9db35Q5kHfFS9xCe1UVrQSsdoZf7cRI6zTpymQHRpxh0cAEzEH7FMwZAQwe8OC
xj2MFQw8cggKzgWvoMK+oo5PsieHE5Fl77qR+Q+KpYFKUDrU6wSox90izigmBDAE
qMfdIs4oJos5tVQW8ER8L7d94Qfc0qYuiA6lPuti1Xy0OQKV28mUOreGlvpQTBEE
YQQdHGTwaM9F/6KmOoG3wT9riEej537xT+Pbf8r+DL0Q6Ogm4DQ21kaq74ey4kfU
rx6Kvh11IPnCpFyx646Vz9VSYrcLKf7sWGThnAVP+ZEpKA5GRiF3kYERQoIDQSY8
UxUCMQCMuR6CozhtKA9db35Q5kHfFS9xCe1UVrMfFm5srAQlp886tq9rf8MQO4gy
AukEZWUCAQEENzA1AgEBBDB5HVMmAiyXDGqBKoKEHNIk02EMVKKdHqXG6kDInWC/
R4ZVuXK3T8DqJrRX7RHxndk=
-----END PRIVATE KEY-----`,
    decoded: {
      version: 0n,
      algorithm: {
        info: {
          TAG: 'EC',
          data: {
            TAG: 'specifiedCurve',
            data: {
              version: 1n,
              fieldId: {
                info: {
                  TAG: 'primeField',
                  data: 21659270770119316173069236842332604979796116387017648600081618503821089934025961822236561982844534088440708417973331n,
                },
              },
              curve: {
                a: new Uint8Array([
                  123, 195, 130, 198, 61, 140, 21, 12, 60, 114, 8, 10, 206, 5, 175, 160, 194, 190,
                  162, 142, 79, 178, 39, 135, 19, 145, 101, 239, 186, 145, 249, 15, 138, 165, 129,
                  74, 80, 58, 212, 235, 4, 168, 199, 221, 34, 206, 40, 38,
                ]),
                b: new Uint8Array([
                  4, 168, 199, 221, 34, 206, 40, 38, 139, 57, 181, 84, 22, 240, 68, 124, 47, 183,
                  125, 225, 7, 220, 210, 166, 46, 136, 14, 165, 62, 235, 98, 213, 124, 180, 57, 2,
                  149, 219, 201, 148, 58, 183, 134, 150, 250, 80, 76, 17,
                ]),
                seed: undefined,
              },
              base: new Uint8Array([
                4, 29, 28, 100, 240, 104, 207, 69, 255, 162, 166, 58, 129, 183, 193, 63, 107, 136,
                71, 163, 231, 126, 241, 79, 227, 219, 127, 202, 254, 12, 189, 16, 232, 232, 38, 224,
                52, 54, 214, 70, 170, 239, 135, 178, 226, 71, 212, 175, 30, 138, 190, 29, 117, 32,
                249, 194, 164, 92, 177, 235, 142, 149, 207, 213, 82, 98, 183, 11, 41, 254, 236, 88,
                100, 225, 156, 5, 79, 249, 145, 41, 40, 14, 70, 70, 33, 119, 145, 129, 17, 66, 130,
                3, 65, 38, 60, 83, 21,
              ]),
              order:
                21659270770119316173069236842332604979796116387017648600075645274821611501358515537962695117368903252229601718723941n,
              cofactor: 1n,
              hash: undefined,
              rest: Uint8Array.of(),
            },
          },
        },
      },
      privateKey: {
        TAG: 'struct',
        data: {
          version: 1n,
          privateKey: new Uint8Array([
            121, 29, 83, 38, 2, 44, 151, 12, 106, 129, 42, 130, 132, 28, 210, 36, 211, 97, 12, 84,
            162, 157, 30, 165, 198, 234, 64, 200, 157, 96, 191, 71, 134, 85, 185, 114, 183, 79, 192,
            234, 38, 180, 87, 237, 17, 241, 157, 217,
          ]),
          parameters: undefined,
          publicKey: undefined,
        },
      },
      attributes: undefined,
      publicKey: undefined,
    },
  },

  {
    name: 'rsa-40bitrc2.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICojAcBgoqhkiG9w0BDAEGMA4ECB9AcawAQml3AgIB5ASCAoD7irNdXxakUVL0
5i77zxkcoRSXThYfMwWhp20viHg+jOn6tLQB+ZODSvGuR21iDAcK3lPbxYBrDz3h
vgAcLJPmbTQPqmcvkNXtcN2b86NMalOm24SJzjKRv1/8gRC4w2W9BY9OOagugTzs
lXfXNEf2eTx0OiTV0Nught4j6Vt4pEA4ZvLBer6a3k4/BTjm9uvwq4oRGsfeixkn
VJ27dz5ZyUmwVyzfCQww1gAAMQIX/LAPQKfkAiBuYfHHP3H/tiOIGj7Xmt3Ktknu
j1uAoNUX6/IYQwrS87HQ1txTl19p6HMqnIBncalVRk1VfkckNCILw3c9P8xzxSB0
sRep7f0sh/JAai2CF+nSLlLsfRoPNwBO0kvJZDeXRxKCOwmjK3DdwWuKHpar3ccF
4cgS7dVK0tYur6XoqR/AqfqG8PuP6bbwZWB+i+irmPI24v+177AOYVkrUngeYWOP
VKkX8Yupl9f3jTBVP1/YSlOaXZ3zXn6BV52mPjJHGY1GkTuWJ7ZCLzSruhBVsauG
mhoVAp8AaYoIHfJHGvcZHCZvMMjINVjkkpQBq4sl/OQ+K1E30Q4Amfc8s12T+yWJ
ypn8BhmxeAy4NbAYp4gc/u61rh22nSz8nswPNyR/mMpK60Wp61oFWr7QL9ABAoQJ
09jPzumO/B9WQ6CQvZ0fNNvBfVSg3/OzhY0quznHGalJqahORtP1lcV1m5mrCd1Z
8NWf7hIA/paMntlrkgRXAB36K/AqvS563TMDPWn71Jj7bErPw+8WlIeuEs6I8265
sQpvNvpamuxunxRTnjeXyC1x4ZU+LDZT2ZG1y1G/mGYm9nRVPkvdgn0OHzQEgD9Q
R1QRZL+9
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'rsa-aes-192-cbc.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI8i+OtR0wbD0CAggA
MAwGCCqGSIb3DQIKBQAwHQYJYIZIAWUDBAEWBBBHvOq1294P18bekzyYVp4QBIIE
0AJnZHjPZcPYKdSNaNfPfc2s+UmTgYeLCun5sd+9KIYyozJ2ljZTijsdp/hItWTu
DmHrfLTLV8mtL/OFJ83u0rDoHVfSrDLwFMAy/nmbtlLYPFEfU9MQ8s2OtvKuobmI
b3x7b+MrTlG5ConptsQQw5tl3dza9DZGfHUnO2EzXorytSMLFCGeQskzbN7Y/Sbf
2+IL5yoifcfPddTbKDyTa77K2516tK2+WTU/VUfv2r5d5SiivZLuMjIYrbneHYoq
hW30BZozCqJKJ5G2jwNjLUjPirA6qtS0Y1tIb5rRjZ0pSy1X5oIQL2laZLrDo9gP
/Ud8m1k2nv9Uv9HPM+G4xCMSiJVaptYPyzFQACcSdA/BVUdBC0EwzIj2nbaoAlM0
+sZ2Asbohnds/AsDz+/b6MaMKg9Onoort0zF/HtpSII6+WSmvGOaV2469JEIvZlU
JIn1YugpDPIe6/B35J9sYfvVNKVsvJntCKxmcz6Nw2VvPKXC3o/bseBqAhLKDMZZ
Hr3id3O7bN2ng3lKuGofmQeMYnW4zb4coXytdc/XCvf63xE0NsUEBFuRMpc9iocC
2RMBEzNyE4tnigI61T/zkpwgBic1p/isGoXMdPWl+Z+IAIYgyxOVwO9g78yVW9tp
1xF9WzJrGHKNT9RLmINyo3jt/wRj8Q+T0EG45cDQcHwpyXdNS614hUCIaeTvQcR9
8F+f4D8IvL+GJt2EtbqL+D687X/hptNehpFf+uxGiHQfrtOvYS/ArNrewa1ts9nq
SMAE7Hb7MzFdnhDqRFBa+//H1jvNkDx3qXfb1/MNE8pR6vjcueKKQ0BzlrNX1O2C
oz0OCMeDfXZhWdYmNjLNcdbonrvq5Z9nOUEdw2lNWELT4lOAmqgA/xBFdQa4glCx
WS1r6DyjgTdGlPbcGugRuTcYXNx6iikWzoS1369maz+WV9qW7r8kA1Fs7WUiYnOb
I1E06yQKVANe+t2SQYN2jPK3EsFFOBxG9tlcXbZVxvx9m6XJR7f7YnLPN+b0f1qF
cT2c5IhK5pKRiZds82lWBnk+eli+qUXILIBbDvBmY4PyPk+kyewAHI1HWBfoSH/3
aLIV6JPgwjAJKnr0++jUqETID/yGyLHNNy1u4ALyAfbFVU//RGmwAxhrBNPdVVGb
rBfKL+VL8Hu/m5XWXez0nHKyD8J1i/XO1OutBsXYxEn6Xnu9rJn8F6nJ+XB3zt6K
QdkUp85t3GM0wyizuPRWJrSVfYyjV41yEBXqe2lgqTT9dpvpgIRtvUeq83e8PD/3
6qKoeTv+3cppCFZ3vLArGvsvRTcbfc3YEzXxz6gc/1HTzd8UpCnA/9+jepG3IzRL
1bLs8QVzIBAT/UpuC6QWUdAR/JZMEFLU5FnRh6oXuh2Zys66Ot7LyNhnGlSEPlXI
polURx0bew+QigBGiH7NpyMgRi9Wh+1HOA/wsAp4X7O+DhaX6vdiDbQoilN1LclU
TRFShpuaxwRA1ek2Jz3JLn7wCsGaVXrd2v/CgrxofCWzGjR2RWj9hAkV4eoJ3G6A
x3DhMRrqXc/O3ON9TyhKBZP1g35In5bZmBUv/o+7eYV7KDETxPwsD3A+dCqUJObU
kyZehu2DsfyZFI98SnecRpb0M0vi6ZZueCykOVec6xkX
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'rsa-pbe-3des-long-salt.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIJdjAoBgoqhkiG9w0BDAEDMBoEFGDV4FIOX7x+wuD8+HxUyvCh7beeAgIIAASC
CUilyA7jms8ptwpQ8qkRgFZUC6nM3wHnMNgTiSCPUCPJBVVQH93tKwskpjVopy/z
moLY7YAkCaOoK0hBuq7RPG7Q5Fu/c3cJygEETf5CGBBddEyu79KKBngg/RzQRBYM
0zW6GJzYhlt6nmbAg2bc6OS0pRnwdpcMlsbQ9N3t3MCS4TqnK8r7q22z/jVUc4qn
N/lXMKR1dEGq78rzSx2jWQtuL0ABePAWaRMCLtktNE4X5+INW+wfKFC6N/e7NRvE
Xyc/zRpz8vcpPo2yo7d3doCshk6GgZ+wmivpJvVX6rc738VXih9aYr1BC3OqkApM
mPL99kpIY8kGxuU+Udlz/rOW/+qwfTxitf4ztxRsaQkxtqoehEzF05TFJJoDRPve
nXmfKBPC9iweceulRXLUXrrdis19WFfYkY9bFxGc6VJCahLk3cSS4Ad2ptShEuK/
BXfwQzo2SWjZplTi/6AtXk3RHUbhK+egBrlnHV/yb0K5XuFEPwI/HtRFwosnKpGY
WGgwgzQQp3tXjTGRKgihzW+29/mxlIaQ2o93cgYE/GyWgGT+yLuUbMZ4df+LSYLH
JWmIH4gsjYGRtbfVIIefwoWKnFVaNsLRQ2JNWYBqUMpaWUn+ynbyQ8UJcW1CT8mv
7LzhYWRHq+0NKYGXxt9auPOpdyZZ78mOvuJrCP5remHCA39idoSolR4iTxd7CRZm
4M7xxWSehOht7FAYOR3ujJpILXpTYVcec+jPcd2h18RvwsStOqkigTpJN23UEfCx
mIzxSlm0DqntDpgR3Hd35KOAHo/yMnA2FsuXf/TXL45gJJEs7LzNE8qcstHT6TvH
oznddjij8QYrRvtRFJpczS7Z3uKKWTPfx3QMskOCCXkZNa4DplEy5HkaL5GQHMGH
qsUrFpsRU+8uWt7M1ueBfnBfOsq8NG8YBqzVOtirm8qfq8KetyQdVWQLR/swBdcP
CIaaw9SiGcXX5fi8LD8wo6qsUdXZamKj9a5d0OT+FVnf/prkVicbdDZV8IuFRXSa
ADhC7ItcSELRl/IPDJcqOodIFEtaVsome1u3gxE02ckjTkOnrAOZEYb4OdZOoPcA
o8mc6bxkUCUou1P/DpYHsP93z1lhWGUPt8/aWhZ27qJ9v78ZRxdoWenlYqucRQ35
JorySI33g2+aAKIoVeT/dwWT8mX9UYvNnJB4XqOn745jcB4TNDTQzMQ6aF076kUW
PiOYSza7E63MUp7K+Ye+wEAHzcb/QtZCyJqfav5e/h4qaqkmMD7CCyF5OXJUcJu+
fLq2S0q+LDtX3gEE75+rdqmOZqskEBvPuArbJtQYIcP4UtbEyJd311lHxIOJTVRb
iEDkhAgFXSYrbk7cbiBl2tf331CuQNvVph0qREOu/mDDNeHSRCADv78j6Q2D8A/K
kvJohTxbk9GQA0Ek2S2Y1tOWoH6fgK8TZ9dSWncwSjZWB+lpN8+DQVWMzgVxJLK7
fbijbGu5JJvOaw+LDiUhKesmLjjsjgSjKZa12JLMZAK5diZ2mE2mEDqS0yyfBkyR
g0rd2NO5XsLPBSA4Coknnkx4yOxV5AIg8hS8UsDAuI0s7MRnOirrVR4J/06JR7b/
CMrVu7yF/2aYOFW64XxaaOX8jmmSdUYcGzckvQWNcEoNFj9LJa698F7sMj7nZYa/
C2GDbxNwY5HsjV6wlcDW0fKyqz7xFCc7/EUjVeMBtuVKanxuzfgEP0e0mL9NZX0e
j1L4bJikXQw2kSJxxdfRuFloPJypKIcizaRkmZo4ew0PY1Bu3+aEcG/MZK0TBvrK
DrXKaD+H7RArQyFD0jmti/jEMhvq3nkuB4D5SAgyuExMQTHQAE3tm4y076N2qNFR
ODHdSvS34c/JhqZ83PHc16oJBkcrpaUzyyUV+kZTn8PjnIoCUow8ewKgHorULPzU
j7hYPJHvtoXemfjQvVSBKzKojaAtuV5vtTGz1Xpj2XmMrCegVBthixfKKCtXmLlb
D4/mfjTISVXDZZYMH4NHInt00WRoRus7EIJ+M3e1HScCAVejPBu0H+fwPvGUvD43
Jz9pRmcwczM69F4XyhCUjfnqsKzcAK5fX476j6GtAq031U1jn187Oz1KiqCGonjw
Rm3s2Ok6zjlEpEPIVELDaPgErcqD7uryRbSmxqX99Avz0erzV57LFIm/zqPWAwQx
huXFl2yj94Pzp0iTxANEq3msL6syTVVCYwqnAp+4eMyPRQZH3hSj5/Y+6kt8zcYH
GMBluzeQ72bhf4hG76aYZQlcPt1UAROu31gnfmMC7xLHKXHDsNyxJzW+HuOj1IOX
YOXJOyAYXf+LF6Hs1whmrY7dN5upfBfcUWrJTn2oJ9uNtsvXo+VawFQR1K0gdpWK
b4hVJZOqmLhN987YVcaKYkm4jJ4QwA9LKLiQLEz24lMWKdaCBSZoJWa5C+sL0tl2
bO2A7u5vcIS3++zqyt7339swffjfXihy1+0tRZVQBcOayGbHuYIBhfcAOKbn7nNw
fFgXk6G5ylXAKZitCBDJsbfOND4RrkqwJ27rR4wIDXHf3XNENBDAhskt/UH5rR+N
NaYVW7vhQh0f4wUlHRgJPxfB9Wm5uTvAr/vD7p2vuuxQDKGmD7WRY7pAQSWZpU9E
0HlsSyNYdAHTaggUvMdnlj8//ZKQ2vuXdKyXzHiNsPVFkVEdhn5WJkjM+nuuH2oI
RP5XLIrXaIc7aUbg7MH7FepBomeUHc1xFxpI/Q9trQ3g9HWi1Ce93Gm74qwiIArK
i7W5qSumrgzWRizj+4bFqt5UotuDV8xguMvrBgHw9cSsBQX0umiFpLWKMPikbC+h
FSUy7o7OBtlk5p+RIwf1cSKy+agImo2rVTuyexWXqffb3ErePy6jwe/o1oQ1wQfT
qCrmDvv8CsPOiT4wlR2uQ/eNLcJ2b+I6Doos4RNSyKwaZ1Q0NU1TUTNZ7LL4C5h4
YP62e5pgBuzdshbp+1JBDI5gjzpB5XIA8OSh/BVc3Mpu/Au72vPosoMQpk8UyZma
PXk7WvTuf+xFp3GTNatCmkaheE6EjjHrhIcZKsDvCezLnOEKlBSojrL3AGiAFuL9
GdSL1Qkrwwr+Ra/m/UhShsLFQ7N2zb1EDStBQ66uCMYVCFPAvbFysNq5VADK6Kj7
2oCgLQpMQl9P+qBepCyRjb3ZiUS7KgVukhI=
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'rsa-pbewithmd5anddescbc.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIE6TAbBgkqhkiG9w0BBQMwDgQIhYYzsDWw6gECAggABIIEyA65HvBbm8RHj7j3
dMlCfZYpQ+xJ29e2XbrNj6aRLPMAndfz0LGaMS5CC0+DVNyrBAaqCxftFikwBItC
3fIPewrj6RjDBafxJcKpMx2dP5nj1tZk/e0RQqdCk6X2dQmlsB6P+wz0WOyFjrs2
YMoWwaXkZcdtcmUvsrtT/Y+iiIlS6sCl1xHuaGEV06TjZWsUkL3NbZvYDc+2PVIQ
uPTDEidgOLWRz7b7k0Q1lEhhnU5VtFGHvPrfo7WDg88TXu37D2hp4GmRL3fvI9r5
bLkMBn6R4trULqE2paggq8xW/7/RfrLSDgtlRGytOAMcvDRDQxotQgvyP6d+SYIh
xlUsl3HhsjLz8LqdaMLNIU2XqgmPyFNKiH8/Zva4Snw/ZL3LkqQNcPUjM7XqU6qk
jxH1sKIaiPE4bXb+WhhGkg91EsQz313S72tYyglcXMTkkgT5qg/ogujbimtjDvBo
EWgtAI4pNw1DYJsMh8fzbYINVn2r21OKhOaL/j/kZyn0oIrnfFEnCoQf3BrjUwnm
ErhpfDcPpq/WlmOipQHOh/AiydFj0KNVn5Z8DAxTSwnkR4jQE0ZUIMDm66g4x5hD
xdNSxiKkNVDfAARxSRkSKdyZoZgZPVLLW1PuEk+AaC/WrcU0K5eMM1HKOwUAxs3H
f5if/FPF6dI1Wn5/X0GAFWA03B1lotO6R2dthAYedjV7gSZoqKfDNhMFqdAfnZg6
u/2yIYqcSAcmXISJlCeNjZa6Yk6GbzVdUDCPTacwonwoKeNR09guzYVGmjFBdJVq
CwUgWnQdrvc+lmLLie70d84zicLBwaAdRD+XiaRCzjVcg4XOn1pTd2aRzeTQP6Pm
rBCcgobD1VcTN6SpyDbh9xep0IRvLJqtVrA0XJoXwSImkHUNFPPUmHHaFpOx2CJL
bUj/QuYRKiTaNG78YEx6LfNdldfYKGcQs7ntqK6LJ3ZI6ll4mMEU7KoAIx9HLe77
HQFpBE4zCOfGlmtkUv6iDyHI3T/KE5xIx6SjxQC3LgbK0UyJLXEGabv3mXNwOixm
ixj+pmlSeJgZodIJ0ySEOZealDUqiPZ5OLJA9S1YUzhkNwWqgBwBVVWrh+ZptiRy
kUXZRHd9RLM1I80jQavaWtclqbjpKcnsVtZgKTvL0nCQ2obeKkhkrGmW9gZ75mW7
qZ6ZhAEEM7Woq8x2228e9SY2sLUS1F8HX0gSxgeZcj2Pu/yNVEiueUbA5sDHny8w
nCKcFO2YoJCuy9N5vSGI4oLrfkhYLGD4T49WWHbQ1FxiuXJyHyMvOic3+nvbSXg9
CV8VDTJt0M+t2cfQI1HXtDmtzzZBad2BTcWkp8bK+uaknIkWcvMrOtCQv4s6Weev
9IfDAbVSFTziZhTQkOTMOQl7bRvJxdDWvIU6vJPbvU/1G/k5aT84EgSodsQOiRWP
GCPtd1Ky3r0/q5Wn9YVWLZ1J8lojMeZXRb30rb702Fr88E2EpEXm3LRDtWa04y7M
pzuzrt3wzjG4FtTG6M8i4iZuFhAiRnbpcQAYJzpsAnd7CDhAl1SB8HaUTJAkdP6L
dTPRsndlkMtkW+mgGjiQOh8DKLJyxIsPa42ZSDMxf/y+DVBGAWmdQnlI9R3ejfw0
FQtb3ngwMaEa63Eiag==
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'rsa-rc2-cbc-effective-key-length.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFFzBJBgkqhkiG9w0BBQ0wPDAeBgkqhkiG9w0BBQwwEQQIdEQTzibS3T4CAggA
AgEQMBoGCCqGSIb3DQMCMA4CAgECBAiLFADJWNVGFgSCBMi91CAKKUhya1MYkBAq
nC4LyUuOGpXVBmanWPw2pWB+DteSIzLGCj5X4uzZNLAEe7L5aIx/yxquKGdI75sy
a0Y2zayjoXim+9eql704PCgOYZRACzAefj9TdONFWKPnAdpazxrqAIHxA8/Vx4Gf
XnFVKxUVvpsyqIC+gfyqyAUO3BV2DyQJb7nkbhjAchYIvzG+Aiu8o/MEwMKHxxyk
k7jCzSsX6KZ/FZHFpMtsT0v+7PdGX0/qmSE2nv4NPGu3zFhveJ26w9Xb52ZL0frY
yvZ4IAf6e27oKnuLM7bEOPqDcgPSzR+1ky42FhWfqTQYIQMQ6rQliuFTe5DMDGI/
FN+syeOnmYjMPs0LlP/4wOWP4Xk/vx1dqBe7Xqitqm7Wn48sTIV1vMpdTZU1U06a
Dlam4FH5tHTB+jaGGwFWTmm95pv2XCKRlfYlJuOe7wEnYtx+Sq5BE4gaFlyxWH5+
93KfFqXg7ghv+E818vqHsi46tNyh8kV+bgQGGxiIRogI7aWgfqdO10EUsUt/DTvP
+PKWB37sdwi1OaNw345CLEz/2E0466c7xfKE/lSnwsN1Ng2t0eM2aRhHA3jIWhoX
BVtDegBSVTYRUSYJo/Bh+4YecxX/NyK9eUYUaMF9N0JC+Sz0y4cO9244yDAOfREM
UiiNruEMJ245z3NF0KsLgGAJZyMClraTCJfKHgCI9JDNA9SKnoRt2XT6jnVwniqq
wnV9iiR87FQhyJ77Sr5xYJRRBXSgCJLW3IY3SRGUJH5Uxe9VtMX6kxv1G49WppjK
QHq3yn3SBYyukPCVgma4V8FPr0PsaHMlq+crk8S3pS4/nBgruMfgKKx+R+fr/T1k
Ro4jK38E8kfXOX3YKckzb2C6UXqzZ8/5fKFW9LJ0gOHdwQb18e+R/juTPepOhOlz
2oFrWpk48WnahmeHIcP0AdnRsc+HwYHwUNKLByi09zzv1x27OBAXTgwsGtZvdv/3
8O3dElMfj2AJLGf+nu49tuikAHTJgIn5qNLiY/Mt266t66HKzJRwJHitxQskUg8L
h9eqMw5TmkD9S3u0p/T19z7r9fNrIpc7ms65ehHIbo1Zu4SomMMT07Aqkm/nrNUP
paCqQJhySXCyI0mVPUilz9iZEVWQbeyB1BYrvUIxJBOdq4/2PKJMpR5TooNdUvAQ
Bboj6XBDTLFWpcvviGwg/Bw2TijOI6mkXgMNLohRqpNdA11lwkKSgYLOydAf0AQs
xHAqkBhWlJT3vkj4PcTQaD+wjT4HzqSLN2NASdcTqYpS1c/IfGiesb5c5VBPdszN
cZ7nD0MxG+pN3aCFilM0PRvUxEryebwVOfDVXwdUiMv3qu051LKfejxkH+7v2lqD
DPAv82WrXENz8mIDHrjo7FjKcixBAs4v8zLI255J8WTZvnKlJtgvm9WTw9gLVrs+
bptWsyTb+90XRAfnqHOcjQrZtqhZzuxor6+G38FOW0X4fmrcqDQ1KWP6RkLY/VCe
vlz76G2Hth6iGCsJAzqT/cF+wpQoj6Dpbe1SjLgSUMv9SRQug0QO6AWJnGW2ccNr
qI/3QtnCuY7Dwu+WufvB6sksEBpQRsZTDnsov6Ss0nVjnWfTRLIb043v5p5ntx8d
OSVmpjnO63mLBaQ=
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'rsa-rc2-cbc.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFFjBIBgkqhkiG9w0BBQ0wOzAeBgkqhkiG9w0BBQwwEQQIdEQTzibS3T4CAggA
AgEQMBkGCCqGSIb3DQMCMA0CAToECIsUAMlY1UYWBIIEyL3UIAopSHJrUxiQECqc
LgvJS44aldUGZqdY/DalYH4O15IjMsYKPlfi7Nk0sAR7svlojH/LGq4oZ0jvmzJr
RjbNrKOheKb716qXvTg8KA5hlEALMB5+P1N040VYo+cB2lrPGuoAgfEDz9XHgZ9e
cVUrFRW+mzKogL6B/KrIBQ7cFXYPJAlvueRuGMByFgi/Mb4CK7yj8wTAwofHHKST
uMLNKxfopn8VkcWky2xPS/7s90ZfT+qZITae/g08a7fMWG94nbrD1dvnZkvR+tjK
9nggB/p7bugqe4sztsQ4+oNyA9LNH7WTLjYWFZ+pNBghAxDqtCWK4VN7kMwMYj8U
36zJ46eZiMw+zQuU//jA5Y/heT+/HV2oF7teqK2qbtafjyxMhXW8yl1NlTVTTpoO
VqbgUfm0dMH6NoYbAVZOab3mm/ZcIpGV9iUm457vASdi3H5KrkETiBoWXLFYfn73
cp8WpeDuCG/4TzXy+oeyLjq03KHyRX5uBAYbGIhGiAjtpaB+p07XQRSxS38NO8/4
8pYHfux3CLU5o3DfjkIsTP/YTTjrpzvF8oT+VKfCw3U2Da3R4zZpGEcDeMhaGhcF
W0N6AFJVNhFRJgmj8GH7hh5zFf83Ir15RhRowX03QkL5LPTLhw73bjjIMA59EQxS
KI2u4QwnbjnPc0XQqwuAYAlnIwKWtpMIl8oeAIj0kM0D1IqehG3ZdPqOdXCeKqrC
dX2KJHzsVCHInvtKvnFglFEFdKAIktbchjdJEZQkflTF71W0xfqTG/Ubj1ammMpA
erfKfdIFjK6Q8JWCZrhXwU+vQ+xocyWr5yuTxLelLj+cGCu4x+AorH5H5+v9PWRG
jiMrfwTyR9c5fdgpyTNvYLpRerNnz/l8oVb0snSA4d3BBvXx75H+O5M96k6E6XPa
gWtamTjxadqGZ4chw/QB2dGxz4fBgfBQ0osHKLT3PO/XHbs4EBdODCwa1m92//fw
7d0SUx+PYAksZ/6e7j226KQAdMmAifmo0uJj8y3brq3rocrMlHAkeK3FCyRSDwuH
16ozDlOaQP1Le7Sn9PX3Puv182silzuazrl6EchujVm7hKiYwxPTsCqSb+es1Q+l
oKpAmHJJcLIjSZU9SKXP2JkRVZBt7IHUFiu9QjEkE52rj/Y8okylHlOig11S8BAF
uiPpcENMsValy++IbCD8HDZOKM4jqaReAw0uiFGqk10DXWXCQpKBgs7J0B/QBCzE
cCqQGFaUlPe+SPg9xNBoP7CNPgfOpIs3Y0BJ1xOpilLVz8h8aJ6xvlzlUE92zM1x
nucPQzEb6k3doIWKUzQ9G9TESvJ5vBU58NVfB1SIy/eq7TnUsp96PGQf7u/aWoMM
8C/zZatcQ3PyYgMeuOjsWMpyLEECzi/zMsjbnknxZNm+cqUm2C+b1ZPD2AtWuz5u
m1azJNv73RdEB+eoc5yNCtm2qFnO7Givr4bfwU5bRfh+atyoNDUpY/pGQtj9UJ6+
XPvobYe2HqIYKwkDOpP9wX7ClCiPoOlt7VKMuBJQy/1JFC6DRA7oBYmcZbZxw2uo
j/dC2cK5jsPC75a5+8HqySwQGlBGxlMOeyi/pKzSdWOdZ9NEshvTje/mnme3Hx05
JWamOc7reYsFpA==
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha224.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIur3B1wRZWJ0CAggA
MAwGCCqGSIb3DQIIBQAwFAYIKoZIhvcNAwcECEnKPmr6wiNuBIIEyKNZuEXIk0Eo
AC7KnJWaEhSDsr4zte/uGDTeOGRVT6MreaWUH3i/zwHXsavEBsw9ksLYqxXsIeJ9
jfbn24gxlnKC4NR/GyDaIUBnwGlCZKGxoteoXBDXbQTFGLeHKs0ABUqjLZaPKvNB
qt9wQS+zQ8I6zSQyslUfcDr3CZNgHADdmDFiKisAmT1pbtBgPgzmxLNSmx9C1qwG
ejuZ/SJ0YYAdRPkDh1p2yEiAIfRVFTgWcjltcd69yDk7huA/2VCxWJyVDCGrEnlm
UJyybUcXXofneBp/g0J3njaIbIftmYIC+763EKD/dqVIRXVxrkHyYcvZ2nVNUT73
Uflk+JuHIjTO4jHXiPcaPdAEPLeB2D3Geq5ISYOvTzOeurfD16Y9hrN3IHi9gedm
JTcEPkAx2hcb19h74XlV5tcQ5ImsPgLRl0euODN07+nj14AFxCQhuoGx+Yj04NkK
dV/l1rLsbmLiqr4n+y5ezGr0GJARVinLCBehptzxaipXPzRW71IQSddbtlSl1rz5
Npv0HlwGgwTacv7T0ZdWncaw0VjxjXAwHBD82fCiuH3qZAXEa0M4drxROeIncart
MIky9qIRjfImr3oh6GLxNBB3FEFFf+23CO+Qt3vrh0j8sVYn3cpbgHcqv0q4fca7
Sq2okw4RjxcDHyLgWiR20tUkqJT8FYQr0u0Ay+LT2YVVO7+EQVqvlraQcOS4Fkfa
Vnggn6sdyhWWCV1rab0v81qZYBvRoUK/ynICKCbXaJ8d1mirdNGgs3FxpVAiUPZ6
LYZ21Uwtj9OoeEQ06GPKq60xHjUmTsNiEkh31AIlSAgdsN/0+pUiD6f1lCWfiLUi
8MuFUDXqkqXAvnJW2/mKrLvcx7Ebm02rkNw7AdAnUnEx9BGxD1B0TVZtRid6mPSO
kXv7adNyBH7qoI9vGGQ1ptNRcNxhxqgGgtfwI+0mV6P6G8BJMl8urZYN8aAC7dJX
/k9EICTUcOU6nIyFFe8tk4kkcjdo9BNkgB4JjANT4ptR2w950tYVqDMHBm1eKPBC
bL3SnDDm4Cplsy7zAdUPsCe7/Zk3K2SJwUj/lDUTDGCTtq4RplfDEBWb218XWgA6
rHgi9/EFH3YCZM8EiE9Mnx9UafdnfKhk3tm3I5nKo56C54os/EKL8W+lhXYdK9dz
peehTsjEQjF0/1OE0097XlCShP8E0bdluoFkD8mKYC7mGv0muJLuHdGMEaCKzKoS
LBKpZNYdOu2wlFfCkf8zSWO4eZYKbSUL88AoEM7A/kquQsQnb80FkciPFazlF9lb
ihxh3YD+TNH58zpYvqgOZkBflW4kKIYbyWOm+ARMq+eVph1aNKMdzeW7Gmf1Fab3
SQmfuEBAfS8u5ghW3J57q8gSJSGB8bpYWAmNGGeQE2g8C6HTxJ34kU2HoFLo8a1/
cqrExWl0/lkhwqc7PpvJbKIMxVOOXtVMrzG2XBCkfQSmtwwOqH1g6AZv+6sXyLZJ
PmvQ+R/23+eDqp/lymz0G6F6B10pldgqt5FHYxGaVEp7GIx6L+GtI6G2qGxpHJA9
x//r3gdd21Fd6y7qHYOLO4fEYAe2sN0mJVjxFLsg9AhCzfxKEHsit5LMdTkGFRG0
XGP/QsVNcWJaYyaKTXaTCQ==
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha384.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIYFcs8Uhn2poCAggA
MAwGCCqGSIb3DQIKBQAwFAYIKoZIhvcNAwcECKCBLl+C+3nCBIIEyEnIPlXdh1e3
+cnyhX7dCRzR/NsygcRBJUPdwRUMAaOo/t+oZxFmHnblchxQ+pFoHrI9GVwg8uID
meEHlzSSKt8kOTvJ3C148jRFJy61YH6k5GEN+z5ihS9uTszaXRUlEsGfP1/SzWY9
ME+pX+0kwJ4az87mYKyNUwK4U5d65Ic30pvRJc4unvFtRz6wtwqU+EV283pXHfyc
VNgQFjb1IPHEz/PSuE9p94mQvdIbVmuK2dRiMag/HcABvVhxzLldKyEHHhrHR0pa
gc41+3HVjz0b6RPE24zNrxA9bU+1URGwlkIlh7Jpc/ZuYRj6LQ33xUdYZcMZw0b4
pSFJcUgX+GUXLyWLqhIxxc+GIeL2Vt5G0ea5KEqxOvSj2bJV2/JA0KtmrcIjX5Kz
d/9bAvxatcqIikVNVkQpUc1glKiIBfVrmyJ4XUlX9i5F3cgl18zrYUI4zPSBn8o5
yxSfCuIMx+3zS4BiyugGNOclIbpLMjQuMrXxrt7S+QlXfdbXvyNfxa3qfqf7/P2k
ykxl0z1bjvkck6XoFGXdb13isUEtY2NjujZKZe55BLGqr7FsIIQSTAHilwMpK+CV
fA1EL4ck1+7FV+l8fJ0nN1Li1xOnDeAFuO2m91uibNMYPvRSoX9c+HQKXCdGfiuk
5tfNaq8bbXeIJ/P8wTjMZqI2l6HZRuXvvmRHN2zZ4BSsT3+61xtvSTISEimDSm5T
hYY583LG5lpFoOC0Y4EUw/ltmQpKW7AGkLg7SyC9oKvoeWM4c2t8HrL3iKPXtkwd
A/iEfZTxzmR57u+ZMlbws0evPiZQml8voJnuT6qwbos7g7V/Pc3Rj+b84JZcI2Jz
D89/VudIHfFDTXC/gcSRG4bd0glILJHT9FOCAlX5TEuRyeWasoVOV+m3Pi8vQM1u
tCsjE9UdoIdhoI5j94VhzHApdD4fePcQW9DysYa2R10gWIZKUvhUHH3FWLR2X2gK
Wiz5YkhEGXBRtDHd4cx8EM1bJMKwFyYXjXTPGfGlGiPt8b9u4F++IlsKcgGgPIvh
2rIm4jHuN3LRRlFkJ5B0kuOOxZ6GBfxasS+Ix4DZoIfqZsGNI5Wu2ikGZOKxX7Ij
G9RvcdpVV8C2Y+M9qI2+x93WAtQ+NRJo4/+gJ0O9bVUhjjAmIHu2bMtbvr9aPJhd
OpB9VQxB3c5mEXkNOV52oOGnIGVjbJMb4e3/MRpWtTFVcX6r200Gn6Hn3MnWZXdd
H7pOpAowTcTlFcbJ0WWjfZygj5HKKUOFzPYNnXKizjzQhF6yK0mphKFY+8tpFQqB
mV/1HlWJTSsAmh/FN21B2qq+KRiwMdpzKIEKC47mK+dzzo1mrTqmExvbiaLG8upr
KMb/lEnSCasiZKTh71J3+5vUE+Nw73rYNZcdh7fj+GBK9KJ3hdKwYc/9yyQx1Lua
4aXnUM6vQAsV+OLYNQE8vXMRtuftbPbV9sqiBLPIc/0P2EJ9mbEye8FM+koHUCKo
xtJe5SK36DMwAas6tjimouVgWTcAdbq9r8jQlCJ1WxXPUcCJdv6pFQUGKQ+34TMK
uWOhErUNRdqel9DthU5ig5dZs2DqlzbRzWYosZc1B6Q4/nua2JiBi8IeqtPILr2a
JYJ9DNzxn07lcFHiVgrJuA==
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha512.pem',
    type: 'pkcs8',
    pem: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI9z8gVJbtqxwCAggA
MAwGCCqGSIb3DQILBQAwFAYIKoZIhvcNAwcECCQqQHRFeFdeBIIEyMJpY0A21GrC
pKBL07F7zOyuFIdwQT2f0wnL6lPWvUg02M2jlHCLDYlciCeUhE9fHUDA67814lvM
dlZ8KgCsp+2mqkoZB/hRvvS+ZdUqkwSI1J3Wt5hz4dKq0cebJWpDAcY/+031+zTU
9iCshfsWAGdlcAIBZOEXDwejNfIayp5cFKvQqg7kmED+KN71QmSVmVyKafh5m0SC
2Y3CoZTQ1982VImx4ZOfh+r86XNkrKLj3KYC1K6DR64Uwq2yLNoypTjdUig81ste
Dhqm+0YXVN4dxXCLF4desKWxN9v78VmCuHvYkRyunj9Q43GVp51cMQfFRBLWIqnB
OrT8k020lne0MxO1xju2sr3GWA4Wn6MLqrxSdfTq+P7ZYcSh2BchkDPslxi5gNPS
Hv5o28rkVW/K34UQw72Kur5JGMRNwJpye2rSPUbtLKb0z81nPzJMP+BCl9DttTr2
zDkkn/AFBRuKH0uWrKv+9f7FDu4hxsdFFnLcD6kWlX/V37b5tYAcy9Atd7lykw8F
K8wAoYZHyzYaIR5otYV5XgjMcw+z9U+5t4ouXSYght88Y10Tq1IYnIx0I55KaV44
uCdrptsKnXXWvIux8h8p/SUwvJOrECc/nYxyfS42diH3V3VGV78fw6n74nDOYnLK
ruIASg92TXUp3Qd8xdoiqdTfx8ZCgNy0mmrYycrP3cUciAYURuKWjjdTN++fk2Vx
Rw1KTFgTf0Z3dxEMIKDHHDiGUbO9cE8oEMWCv0YJ9n97suoIN3vOcifxG/93RE5M
1xe91IEY494/DdgsMqb0D4T0G5rbFHnNY8bTDKIDpvZKzcbnm9vnxPi7Q1S1kkJG
230apDz1Rln0AFO51SAVS8QoF5wP69cL9vrC5miVh3mwqkDVoHnLNpJrT1o/XcVR
Jl1j1t9lgFNJhVTltTPza4FydXRe2ZBCNKpDci1jFtD8KYZGOCc+PQtJ0Wtcx4qJ
KVGO52gUT+DSxmaKd+3RyG7MsDw1CPT8inHkACa2G+GGQvqukbjLppQDkvmUPkTa
fEotMYqnlvqznwiWURl962lyRJJsxClC6Q9R7Pe7pxohsthIHgZFMMuECenUdhYj
3TdqtKKdbShoF2SBnwYUVScH2VR2ZE8ZLlldNIA+WswG4x242NoemE76JC6DyUQN
WaxFLL813TmiLYtRq1QZsiqCqr2jRBMJA4cdCt4jMZXpLd8heviNtcPmf6uEpHV6
VBQmun8dCQAUeCHKsrkOLnAcnrIl9gPlyR6qVAI8tnfs4IezjnvAh7+cN8cQ1AZw
xRvoAHJfR7GMT7Rp/GTLrSYU+swlnjrDLQ7DwZ6seOVyzmKo1zRjysQ7qF5m6ELp
hlu6ED1/VZZw2kSbv6BVzYmWHCGnuyl/n9zXImMR9vcM/uTogjc/38F4zBlSyz78
wHy4EWMn2jWyRYYFfwwLvrxmU1IHkNUKYfaM6qeq7F8R7cqbZhZ1cCrAGcIhPrPy
ig7iEmTblRw+ARmY+cjUuJtbU/a38kEfCMIbKKnUg4vUnO6s2XCGG9TpmcLR1Ti/
80tOsEuvg5ZJB3FFGHhSH1gDMAKQwCkcP4wbP/YhzBhq9WU24AA82RtOsFV4xjFV
ptyV+PmEpJl0DpDeIv0I+w==
-----END ENCRYPTED PRIVATE KEY-----`,
  },

  {
    name: 'rsa_pss_2048.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIIEvAIBADALBgkqhkiG9w0BAQoEggSoMIIEpAIBAAKCAQEAt1jpboUoNppBVamc
+nA+zEjljn/gPbRFCvyveRd8Yr0p8y1mlmjKXcQlXcHPVM4TopgFXqDykIHXxJxL
V56ysb4KUGe0nxpmhEso5ZGUgkDIIoH0NAQAsS8rS2ZzNJcLrLGrMY6DRgFsa+G6
h2DvMwglnsX++a8FIm7Vu+OZnfWpDEuhJU4TRtHVviJSYkFMckyYBB48k1MU+0b4
pezHconZmMEisBFFbwarNvowf2i/tRESe3myKXfiJsZZ2UzdE3FqycSgw1tx8qV/
Z8myozUWuihIdw8TGbbsJhEeVFxQEP/DVzC6HHDI3EVpr2jPYeIE60hhZwM7jUmQ
scLerQIDAQABAoIBABHHBrdHJPuKYGxgak6kJIqlRNDY2FLTUGB82LzKiK6APfmM
vOY3meuWkbLyEFreMmwxBlBDFdHqLRQsvWdtBVGTpidertZAdpE8QmZkA7zPcDhc
VmPWwYRsmOuSLvh57tFbVsiS02qtx6f8Npxay0as8wzekNb/3+UTTxkNO/9jQOct
14d8zTRJo6eL93Iv1zyU1lj9utwABCF+NAcAxFT4fdeFjmhx14oq8jekrN67pE/o
4yurS0r2XtQBKjse15u/rQ9NHM5CL6m6ytJ8Kdvcy8qiBia9eRE+P8/omd+8cDfj
we1M751jyG7P5jlGCJVEWpiP7DcXb+Kdhndx3ucCgYEA4pBxftTQ3LH9delpVRQH
rxJdbzARXVbdZf42vnD2SvO5ObFh0XYGV4xnk7DCkLfJsMdH4QPL27FxlCyhg3cz
o15uETHjADVDDb+OtMU7BsK5ujYPnYHzgKJnwcGOr6k3z8cc8OaJRyY6bdX5olfv
pgrZBcc6aN9gRa6bEA7aBp8CgYEAzysRZgrxAj7nrII2DxX5QqH7Fk2xJVhsaZMd
516lvSU+xnUVeaJLOhtTPLmlr6LcB6zbN9nB+4WihgprfYUf51uleF9+W23ECOn4
kxvw2w0c7ICjn9PoHS8ApSi6W80H8J0zBP9GBRFEzi3x0VNk3OeQr9H9iv2Ro2Gd
uEsSUzMCgYEA0FMq2QmMp3HOcm5WWVGaoyNK4KMdRGtMFq2C3uf1wAONLHxrSnOw
7y1+S/I7ZWBpR3BmKoQYHgFyQ2IqfTzNMYnxwUPSy+0to+WgrZ2xYc0JhCyTfSvx
oDU1HJcCwYjidd5LQUNptQ90qGwZJ2qeRFozJboEfkvvNQORN1nAplcCgYB13HXA
jTcCZRFe9pGU0ZaGzyrPTJIcwgqjobwglptKWbc2JwR5t9h+jW80nBXkL45om3H4
e12+IBAPnDv9JFC7SkuAiSuVDoS54Yq2/u1vYi1za9grJN7oQ4ZlcB9d/O6oeHa/
QA/w8BsqBb+OrJg0iVWqgZhyi8JgpjeZ0rPxOwKBgQCeo9gT4oQ4GoK6exhsVz4d
SYUxOf7zp5AxEVTgACX2ubyrcUOUuE/muy/2QVBzcnuFRGVa0Kfo+sE7OnNhAYkx
rI2R9pds8vCjHaoSFAznyaR9Am2DuXsRSc4Qo0KQujvFzAE4fXRslqyA35gTZ1Z+
u+Cs8ivM7mJcroeZp4pebA==
-----END PRIVATE KEY-----`,
    notImplemented: true,
  },

  {
    name: 'rsa_pss_2048_hash.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIIEzAIBADAeBgkqhkiG9w0BAQowEaAPMA0GCWCGSAFlAwQCAQUABIIEpTCCBKEC
AQACggEBAKYWKqcVytq9mcB+SX/LCONdaO0xdP6J6lpv0qUfn43VUo3JjWNtGA9k
ZLejx/VtcUgiQrYQbw8dvBclxc2anra/487Wv2RLH4F8uFJa57M9kMvl6Qw1DztY
8KhNwdFTI2jRE6yvUYYSFdnBO9J0WZ48yPuJTgnou3XnMAAoUDjnnpf5qFLSQRxM
ikmPU8GNWMzDT1TBNLG576cMHOqm9yv8l4Pi21F/awFulpaOwmbKxXSY+JDV0XWC
jT3ktYoQlhoil3taJRvRMHFMLyjDc/RelE+75wM72cRMu/5M1z8Gseqov8neb7WX
TmYPkcpI4HaD/1mu6vlpPk6pwuVol60CAwEAAQKB/2SQY8U5GvEH6TSR8zqRbAj4
CoXwsYwmsrmvMlQdGzFwGMUVXEHAh3bCDczYVBMKWVBm5/mtmSy+NwGresfK3d3F
nkXDHjUosHNc5THjiWfjD4y6QnC690VvrBXXpwOtBc44/MOdSwCZmqWdj6XYOnwZ
z/zaiSUN7jk9EFvRfmVJRJ1I0dh1MmWEmxmi7tGZ/TkSDrDo3ct2vvCyMqOPS/N4
KKNMi1Y081hZn26asCR/MH/lEYNQn46qq+dU0CREG6phXYuaiXymtIYuclIflwnQ
WKSIKqswX4oazJs6vgk89SPJHlb9o3zFZpi8SvyJGhcJ8VupYG4D9nysIv1lwQKB
gQDRrpJUv+iF4eOdpzr+dKju9meSySf6Z+Zui2ILH9UFZ+zthuPbnnVkmwJmcP1m
R2KOZ1V15UjEcbpr4/KCYu9Xvk9iTMfq/F4OaOXfRuY8cLwzAdyUNPjHPOkTdmvr
aULQaQIWQpPhI8ZVbqzRlTllli//9rHz6IZFVjDZWvLQTQKBgQDKxkvmnZ9v/GFJ
EsZC0KHwSxyqG+QImDO6AB4SL8Ym07QwQvU41PRZ9cH4tOcU2S7Bu1Hld6A2A1fv
nyuQafecVn89eyk4F3Mj/Ypo4bHGVYzl1h8StvWckYLNhHzOndlAvQ5nUICJsRLa
ToP6L37oIT/sDM0Md1Ls/HV/7V+U4QKBgA5qrFD7aOdboqTCTMIWD09uzaw//Gmx
HxzWpIUTSTg37whdz+jXukaSidW1SxbvLY2Q+UVD4H7xOtoUMCZa2w3zXc3qbYxw
kZ74A2YYn9fkAGyZYismgTxhqbzW1ZC4Cgn+TlBtf3FpXkeddnBqjCm5687zjUSx
5hl6VZ18LVm5AoGBALvnlBBqAoRo8NIhZr4lzdr6D98HJ4JbYJu9XiBmSw5R4klS
0yFOHf17QruxD+5+79gxOMwW1c0XvhZcfqc9u2oRsamMhv7mpBk261sTwoTTZFTb
3kGeb+4d3YOLgYiKN/fI+h79N4/hGmJYne5qswRzQ2P/3Mfvj1XzAQOCOa+hAoGA
HXGz2ulswnp+X/Vi92H+xZUPR/VDPoWaUEXXGr9ZnlGo+u3tyfpwzJKFjBDQ09lD
vAvNl4s4jC9oorbOrOcMcN1GTo6ZLvAK7fQc0oeiWUkAfi35cxDvVE9r2kbn3Gjc
10VfBns4ejF/bqy7pwpm3LG2BxPIm1B+dnesNbeQ8oU=
-----END PRIVATE KEY-----`,
    notImplemented: true,
  },

  {
    name: 'rsa_pss_2048_hash_mask.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIIE7AIBADA8BgkqhkiG9w0BAQowL6APMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZI
hvcNAQEIMA0GCWCGSAFlAwQCAQUABIIEpzCCBKMCAQACggEBALlAN/dJwsP7y8N0
mKBKaQb5Hjtbu7KrvFamXA6g0IzUPHESwisYD45VeD1OJ4Hx9eR61Cbhvvdmn81n
1C2tRuBrP8tsbnvt+n35w3BXqqQ+ByAdAvsHF4FpP4zEdhH8tfn6ZSEcqLzXH9HK
M50i1OcAEDvXh+V5t78uWIrt9V8vCw//1ViHhqfprttxybWDXnt7J/FYSKLr+1Le
f9p8vgmtPt2K5pvMa2IGsXz8fWwMGZti64RxXa2k3hno/ove/sxOSefDfpXI2yJn
xlA4XuFOfK6uHz9k6cFDlQdStqznWRj25RGZRW58KE0rjZruVJ/2dsaXe1RB7ps2
3JElBZsCAwEAAQKCAQBEm9QeceMAUrEUoookU2qyenEH6uGJOrF2JgbSJB0ZC0GX
Xysqaq7YOC9gBSH8rnAzPop0HAdt+UQV/u5GPHaThyUJYg9JNsoe/fG0GcPJMG/T
JOuFrQq3kxNGPzy7TKzY+DOcH9Een03ZlNmoyM2xAAUDJL/f7URwOenxClBl/5Lm
9hnS4NE5B73M6iByP3lUeG8YLqoqJClMx7mN6EAuiJgjDubuaRJU94rqvZJsofwU
5Ka2MHtOgGb3ylPled5wuRR+gm6bbzEtYDvLGqwS6IlEeamW0YfgufJct+MtbMa4
AzKuacxIS7irVkcQRH8/wvzWKUtMO24mCPYtM6MBAoGBALmFplhqGgD5TA5suVCC
aLAywp/t8a3aFTXSAaIc3t7yCjMNlNvYANIpy1D6xzO7eDwInJUlJzBEjxjewwce
dC2hKCRkVC0gg8Q+yUI06gQIgaJuobFwFT95l7lchhiJd0ss0YzETH1ujTbhcii2
+y9EFw8R5jgF6z1ymQkmQHI5AoGBAP+gMVD16NaUiHXbe7/yIn1490UuHoWY7jEo
l/KbVy8CnmtffyI//5Ej4JanlQBXxDS/JjxwQg+4cdo9KOF9z1psNXK5Bo1jZ7hB
GBdPNtKE4XsauRW3D+PNIvdFxrZiC8VOwy+dfsnVfd4bvvALJcb6+/XeepI5gsvO
bUO+J2ZzAoGAF7X1JKeq2yUBi3Zp2NhR+PMD3NzUXpvYyiAlBUsbUPMuSogZ1l8s
+69LxPXIL9xt6X5QRN+SuqCIiW0vD+Hch1hpgP0xpPLa5GIB5uxMXGeZ6eCp2bux
e4NW2OHyYYBwNrNrtMoB3KYcdj8qD/oS8F+LcumeutpGznuvA3RYGEECgYBdf5dq
OHfwvKVpDl2mKIeLA0rWR/csAHLnEiT5vO3XqQqO1YAn4+azjL7h++vZE0EV1fDD
XIAdReaG36XrTFwig7/M9XY7EufmEhEgvX2c5LOglnaqRaoPNYIbla8IGLabdaKY
8O9mHauLKPTe0gUAUd8E4FpOz7BSoW9/vraklwKBgQCXfOUPAAGxngzPKWyhyaKM
mUshh353Cjzx/NNwr/sBj93WCiDp4SpfHZ8wgrZJ8UCMm2CiCtK2raiPEzrNo2Wg
sphlQSVoCA0WelT99Eq49ouWnUkQWYU2Bpz2/2e7aCuhVYAKLqCfQg2jw82shewa
RYr0V8K4K8DBgXTuOkgxXg==
-----END PRIVATE KEY-----`,
    notImplemented: true,
  },

  {
    name: 'rsa_pss_2048_hash_mask_diff.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIIE6wIBADA8BgkqhkiG9w0BAQowL6APMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZI
hvcNAQEIMA0GCWCGSAFlAwQCAwUABIIEpjCCBKICAQACggEBAMoBLOx8mx942jR3
nSsWLagYH16UVLxiV4E1+noCLLMm99bkWumRIlsJyCEKe9UuekzPrZlICq0VMdMy
dvQGoHBF15YQYuZmMI6Am1afJjNTeV+f9rDotqQ2Ix4S93ngjgNi4BPT70F/dwD1
4Xe32+IHdyrp99+jtMGj5IUUAVhGg4x8xDUj1mD8Ro94MbRb6Acf86SsvyiTpx5W
ZbnOlnzH1fK2qAtpqEWgrypb3MdJPgpZIx9o1ZYuVQBI3RPFZK0p73viEvyl9mO6
QLoqdmcvxo/3mkrMG2HNFESjlo28f4eTVhDxK32Uwo7Yv5WaFxIhYBgyYyGiwkxl
OrFCkO8CAwEAAQKCAQAkfJjeMFWelignsPFJDoz5nz3PShCSJFs04giXkBv90gyT
GpUXOhlQA1DMMwYSB/6cMCjlll8jS0BAKw3UXvwMu3jIyLXscsnTe4RTXZS7UZkL
PiwDYU1YFNU8AeYEdByCnRHnUvEUzg6zNDZg9us3BO0v6anVkc686TsGFIp3pJaF
wnZCDlUMMZq4LrJn7BYFxyU3i13C9b4c2NbscPkkldumrobdOaZwdXaxDCiIuaMV
tM800Yn2tZg8YQyFVvtw9jqrYqUK0myNgWtteqhi9pvuZzelbpnuUaAbvwqwkxSY
CCtEJk9DJUmoT+7T7iVL9oO9Ox4/6ozZUBSUVzjNAoGBAPZJ9SqfKZBmXZ6kmSmM
GPSdZ6JKXtNfsFjqUiIowsBqBOgyDxC5goNlJF4R4aiU6x7C7dqyIe61dalPPZY8
eU6HnfyWUdF6vXHpyBSv6ak9PiNatY/HibPq+snGUCG/TgzXhojnjoeA41OCkSyL
QIMXcWhWYbU48KzCBM3mjIilAoGBANH4Ni1Nmogv3vaZIEPt8lnpyWGGaMCk7GiV
z7IUxgkvfedUJvflpFON/p9DYw/mU4eKzv4Kc2cHfCwvI+O1ftOHRZBEnVdfS9lq
K5dMHSSKtdqtz1hzRbSCWNQ+hockktHRoTnvOxlXsey0a9almBVo3bawfB8RN3U6
gz7WgGsDAoGAZpj2lbPKF8pc86pz13fyKWys8FF04S76gn/SiUJbptZDhwrbdcch
1GS82qcuTxECRUVE2pbcRdm30zkcWcqFai5apQ9ltBMieiK+Y8fIWeUWTpoKCoRA
HAAmSwne9cAA3p6l/8AegtoxWOeKXHkB/do1NxbNCzZWJFGKuM9y+bUCgYBCovKW
uB1GAWNSgdBinp6eeHrH779I/E5m9ryeuMcM3Tyo8OUZIZFgTx0y8FD9F80EpEID
D9AGL7Lx1tgeCVjByxmBqrUAqKbKzk4dSzOoiDkkuKqoWJUTr5Z/bYSGWU4bNttj
JpBr/4/hHnVm/tDgYpKSyznpJi6ijrpec/b3fwKBgD2snVQ/UXV7G8oy7xwgXcLO
PxMa9xUPsmNL3Gytd/L4xaefxW3oENeBM/UU/PfL13zBROSi5Mf7RTiMTwFBSzR1
YCu75tJ2fx8sghjVq1fZCfOQn/StG2IYsx7cVwv5Z7diESjU50QffipZM6WSdJKi
/Ux4TLILXEMvL4V1VX3q
-----END PRIVATE KEY-----`,
    notImplemented: true,
  },

  {
    name: 'rsa_pss_2048_hash_mask_salt.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIIE8QIBADBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZI
hvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASAEggSnMIIEowIBAAKCAQEA4Hw2apS/
fIsG6ESJY8RZ0wW38eb8onfDA3KYnI+uICySrngMVMILd3+TrQjRCcTAeB/9tu9q
zdOoEWGfg51O2nI+DkETD7lCRfMe4GvrfgL7ii3Qu6ozkYBLKAk6zt3PYIsrSEff
DmgK4ef77d0CfDwKMJrJIj4ptiVuRB0rhRtViZ++zJmzocidFI+o29bGEgD85gdM
acIeXfnUnnwVpxLYyNKSWG1oZV2Y00p0BzRYJutWvcJ+diwfsxO62Wh36uwyRaOS
CJ9Cxtm0bn+YwmrSV/uSfCrD0ZREQpB6CnJErOUATI/Vbe0XaQ3VUpgiiS3gZMW1
aCiYMARNKiq4vwIDAQABAoIBAADbQqYSdAjC1tmuGxSiOr2v9sMFSV2+mGnWLmmE
U13i4I8eq3/rd/mj+I9QxJ054bjWhJc/8/ZSQkaU4hbIyEYZuk2FWNuuFzlp6qSP
YHxpGDrd9lZTJPaWkAoeSuWOhYxw4sOGswl8oAt1bM+wkJaiql8bAv0rxovIroDi
HfjMtqibs4liTQyRYFk67nuZ/taFyQkY0KkYqc4+raHeT6DKExLNCKJnvaw5O4j2
kHQaABjRKG+KG++o6h+IIJBkZdkUzLJXu5vY3RVVduH26V/l2ldLmGzD5DqRP3ff
ruYte9xHi2rCr42BnlTpDhFBAqFGL1hsFQwMp5tN7BgmEPUCgYEA5bJCbcMIb+aL
OXCCanDL+jV3o6jAod+9GLfnELYvnDpITT08pXw3HnFF1cS13wV1B+RpvWVNNOrJ
dH1sz2mVCglqO5PPZSuIMuiOSGbDYhNxkTv6OU5sDMjC7dDKZdAYsWm/7bAetUrN
HKz+8qYCUb1GRkh9hdZkNK+fmIDa1f0CgYEA+jEvSGMhmQdDtfLguPZxVSx0NTNg
goPTDHGwazTo+1i2ZTu2JgYJcMFTKFqRFYMHGl7pfXQx4U4z15FaUJahV5xvb8cf
Mi4XvPhOdTlqJcDAJD6N5bk322AZM2rHGkfTaqUn5XvOq4FHs6SgYgJF++C1xzAu
S9J6yyJ/qUe+6GsCgYBuaazy9DCHEcxU9RdLsSLsCG2VNxY5+cH9MtGYv+rM71s3
/bq8VaRtNsf6BQ/jv8zM2WhWyW4+hKoIHA6E+VzSMUpmjxu/pxhWWGGkvfknmO8b
gDg8+cyIrKy/AoF4RXrJNWs0B1gLj4RfR21aGKC+x/wS5t+nyTHr/Yv7E92dxQKB
gCtOeDC/eAFVEJNeByf9AIENwM+0pO/ygYWV6EOmVO2s3WWIgG70fI3X6N0DUDm5
BHG8HA5rHncxYifeMRPh/ut7WI6wmOXGtLUxBeOknIsMYjXj3gv1k4WVjMcppG0Y
IbBEBjPiylNFfXPK+zf7zMFclBp2bI0TUc33msFiedkhAoGBANpL3yiw73HWGjEL
8KHhxPFWjQX6EsUnzkBvymxiOR1f2KpsSC/4iaOsFmqWezYurOCUvs9+PkdZKGs8
jXMwc+3Pbg5FQ4IG0kBvkSjLKWxZUOzjRF5MRW8ilwGQEj+5A8e18kyQtisIh+3S
pyqbyULX0/e0El4YiFjtfxvsWtiy
-----END PRIVATE KEY-----`,
    notImplemented: true,
  },

  {
    name: 'unenc-dsa-pkcs8.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIIBTAIBADCCASwGByqGSM44BAEwggEfAoGBAKoJMMwUWCUiHK/6KKwolBlqJ4M9
5ewhJweRaJQgd3Si57I4sNNvGySZosJYUIPrAUMpJEGNhn+qIS3RBx1NzrJ4J5St
OTzAik1K2n9o1ug5pfzTS05ALYLLioy0D+wxkRv5vTYLA0yqy0xelHmSVzyekAmc
Gw8FlAyr5dLeSaFnAhUArcDoabNvCsATpoH99NSJnWmCBFECgYEAjGtFia+lOk0Q
SL/DRtHzhsp1UhzPct2qJRKGiA7hMgH/SIkLv8M9ebrK7HHnp3hQe9XxpmQi45QV
vgPnEUG6Mk9bkxMZKRgsiKn6QGKDYGbOvnS1xmkMfRARBsJAq369VOTjMB/Qhs5q
2ski+ycTorCIfLoTubxozlz/8kHNMkYEFwIVAKU1qOHQ2Rvq/IvuHZsqOo3jMRID
-----END PRIVATE KEY-----`,
    notImplemented: true,
  },

  {
    name: 'unenc-dsa-pkcs8.pub.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PUBLIC KEY-----
MIIBtzCCASwGByqGSM44BAEwggEfAoGBAKoJMMwUWCUiHK/6KKwolBlqJ4M95ewh
JweRaJQgd3Si57I4sNNvGySZosJYUIPrAUMpJEGNhn+qIS3RBx1NzrJ4J5StOTzA
ik1K2n9o1ug5pfzTS05ALYLLioy0D+wxkRv5vTYLA0yqy0xelHmSVzyekAmcGw8F
lAyr5dLeSaFnAhUArcDoabNvCsATpoH99NSJnWmCBFECgYEAjGtFia+lOk0QSL/D
RtHzhsp1UhzPct2qJRKGiA7hMgH/SIkLv8M9ebrK7HHnp3hQe9XxpmQi45QVvgPn
EUG6Mk9bkxMZKRgsiKn6QGKDYGbOvnS1xmkMfRARBsJAq369VOTjMB/Qhs5q2ski
+ycTorCIfLoTubxozlz/8kHNMkYDgYQAAoGAKyYOqX3GoSrpMsZA5989j/BKigWg
Mk+NXxsj8V+hcP8/QgYRJO/yWGyxG0moLc3BuQ/GqE+xAQnLZ9tdLalxrq8Xvl43
KEVj5MZNnl/ISAJYsxnw3inVTYNQcNnih5FNd9+BSR9EI7YtqYTrP0XrKin86l2u
UlrGq2vM4Ev99bY=
-----END PUBLIC KEY-----`,
    decoded: {
      algorithm: {
        info: {
          TAG: 'DSA',
          data: {
            p: 119403270161302180536910830433131385489100742341988371204429911965507051004519472985079391097501341779322841449447749159274010831179020894844855667708812053917773488077281978133382042065807449931816318540412042219610792654141960755305525689634425822217731428164331916497356318912827542851830502508745972097383n,
            q: 991957392449135186650051486281028896545973601361n,
            g: 98605596054365495213475430993940478642555594370362576082748057932201258943845649080081758081206414905539563994856519611196809531053869427564925241523617236154748761007809142031292750247477206254240996468679515231558023887874122969511096957862127063488288979357900275420195929955671734840763578761950276694598n,
          },
        },
      },
      publicKey: new Uint8Array([
        2, 129, 128, 43, 38, 14, 169, 125, 198, 161, 42, 233, 50, 198, 64, 231, 223, 61, 143, 240,
        74, 138, 5, 160, 50, 79, 141, 95, 27, 35, 241, 95, 161, 112, 255, 63, 66, 6, 17, 36, 239,
        242, 88, 108, 177, 27, 73, 168, 45, 205, 193, 185, 15, 198, 168, 79, 177, 1, 9, 203, 103,
        219, 93, 45, 169, 113, 174, 175, 23, 190, 94, 55, 40, 69, 99, 228, 198, 77, 158, 95, 200,
        72, 2, 88, 179, 25, 240, 222, 41, 213, 77, 131, 80, 112, 217, 226, 135, 145, 77, 119, 223,
        129, 73, 31, 68, 35, 182, 45, 169, 132, 235, 63, 69, 235, 42, 41, 252, 234, 93, 174, 82, 90,
        198, 171, 107, 204, 224, 75, 253, 245, 182,
      ]),
    },
  },

  {
    name: 'unenc-rsa-pkcs8.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALskegl+DrI3Msw5
Z63xnj1rgoPR0KykwBi+jZgAwHv/B0TJyhy6NuEnaf+x442L7lepOqoWQzlUGXyu
aSQU9mT/vHTGZ2xM8QJJaccr4eGho0MU9HePyNCFWjWVrGKpwSEAd6CLlzC0Wiy4
kC9IoAUoS/IPjeyLTQNCddatgcARAgMBAAECgYAA/LlKJgeJUStTcpHgGD6mXjHv
nAwWJELQKDP5+tA8VAQGwBX1G5qzJDGrPGtHQ7DSqdwF4YFZtgTpZmGq1wsAjz3l
v6L4XiVsHiIPtP1B4gMxX9ogxcDzVQ7hyezXPioMAcp7Isus9Csn8HhftcL56BRa
bn6GvWqbIAy6zJcgEQJBAMlZnymKW5/jKth+wkCfqEXlPhGNPO1uq87QZUbYxwdj
tSM09J9+HMfH+WXR9ARCOL46DJ0IJfyjcdmuDDlh9IkCQQDt76up1Tmc7lkb/89I
RBu2MudGJPMEf96VCG11nmcXulyk1OLiTXfO62YpxZbgYrvlrNxEYlSG7WQMztBg
A51JAkBU2RhyJ+S+drsaaigvlVgSxCyotszi/Q0XZMgY18bfPUwanvkqsLkuEv3s
w1HB7an9t3aTQdjIIpQad/acw8OJAkEAjvmnCK21KgTbjQShtQYgNNLPwImxcjG4
OYvP4o6l2k9FHlNCZsQwSymOwWkXKYyK5g+CaKFBs7ZwmXWpJxjk6QJBAInqbm1w
3yVfGD9I2mMQi/6oDJQP3pdWU4mU4h4sdDyRgTQLpkD4yypgjOACt4mTzxifSVT9
fT+a79SkT8FFmZE=
-----END PRIVATE KEY-----`,
    notImplemented: true,
  },

  {
    name: 'unenc-rsa-pkcs8.pub.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7JHoJfg6yNzLMOWet8Z49a4KD
0dCspMAYvo2YAMB7/wdEycocujbhJ2n/seONi+5XqTqqFkM5VBl8rmkkFPZk/7x0
xmdsTPECSWnHK+HhoaNDFPR3j8jQhVo1laxiqcEhAHegi5cwtFosuJAvSKAFKEvy
D43si00DQnXWrYHAEQIDAQAB
-----END PUBLIC KEY-----`,
    decoded: {
      algorithm: { info: { TAG: 'rsaEncryption', data: null } },
      publicKey: new Uint8Array([
        48, 129, 137, 2, 129, 129, 0, 187, 36, 122, 9, 126, 14, 178, 55, 50, 204, 57, 103, 173, 241,
        158, 61, 107, 130, 131, 209, 208, 172, 164, 192, 24, 190, 141, 152, 0, 192, 123, 255, 7, 68,
        201, 202, 28, 186, 54, 225, 39, 105, 255, 177, 227, 141, 139, 238, 87, 169, 58, 170, 22, 67,
        57, 84, 25, 124, 174, 105, 36, 20, 246, 100, 255, 188, 116, 198, 103, 108, 76, 241, 2, 73,
        105, 199, 43, 225, 225, 161, 163, 67, 20, 244, 119, 143, 200, 208, 133, 90, 53, 149, 172,
        98, 169, 193, 33, 0, 119, 160, 139, 151, 48, 180, 90, 44, 184, 144, 47, 72, 160, 5, 40, 75,
        242, 15, 141, 236, 139, 77, 3, 66, 117, 214, 173, 129, 192, 17, 2, 3, 1, 0, 1,
      ]),
    },
  },

  {
    name: 'withdompar_private.pkcs8.pem',
    type: 'pkcs8',
    pem: `-----BEGIN PRIVATE KEY-----
MGACAQAwGAYHKoZIzj0CAQYNKwYBBAHAbQMBAgkAIQRBMD8CAQEEOgG97/hDkXbJ
tgF36JmM7NliJIlDFzTm69KYouwhjPOsh6hKo5NPTtsmHafplOqpUf0TyAhB1Q88
3xA=
-----END PRIVATE KEY-----`,
    decoded: {
      version: 0n,
      algorithm: {
        info: {
          TAG: 'EC',
          data: { TAG: 'namedCurve', data: '1.3.6.1.4.1.8301.3.1.2.9.0.33' },
        },
      },
      privateKey: {
        TAG: 'struct',
        data: {
          version: 1n,
          privateKey: new Uint8Array([
            1, 189, 239, 248, 67, 145, 118, 201, 182, 1, 119, 232, 153, 140, 236, 217, 98, 36, 137,
            67, 23, 52, 230, 235, 210, 152, 162, 236, 33, 140, 243, 172, 135, 168, 74, 163, 147, 79,
            78, 219, 38, 29, 167, 233, 148, 234, 169, 81, 253, 19, 200, 8, 65, 213, 15, 60, 223, 16,
          ]),
          parameters: undefined,
          publicKey: undefined,
        },
      },
      attributes: undefined,
      publicKey: undefined,
    },
  },
];
