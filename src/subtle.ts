import { validateMaxBufferLength } from './Utils';

// async function cipherOrWrap(mode, algorithm, key, data, op) {
//   // We use a Node.js style error here instead of a DOMException because
//   // the WebCrypto spec is not specific what kind of error is to be thrown
//   // in this case. Both Firefox and Chrome throw simple TypeErrors here.
//   // The key algorithm and cipher algorithm must match, and the
//   // key must have the proper usage.
//   if (
//     key.algorithm.name !== algorithm.name ||
//     !ArrayPrototypeIncludes(key.usages, op)
//   ) {
//     throw Error('The requested operation is not valid for the provided key');
//   }

//   // While WebCrypto allows for larger input buffer sizes, we limit
//   // those to sizes that can fit within uint32_t because of limitations
//   // in the OpenSSL API.
//   validateMaxBufferLength(data, 'data');

//   switch (algorithm.name) {
//     case 'RSA-OAEP':
//       return require('internal/crypto/rsa').rsaCipher(
//         mode,
//         key,
//         data,
//         algorithm
//       );
//     case 'AES-CTR':
//     // Fall through
//     case 'AES-CBC':
//     // Fall through
//     case 'AES-GCM':
//       return require('internal/crypto/aes').aesCipher(
//         mode,
//         key,
//         data,
//         algorithm
//       );
//     case 'AES-KW':
//       if (op === 'wrapKey' || op === 'unwrapKey') {
//         return require('internal/crypto/aes').aesCipher(
//           mode,
//           key,
//           data,
//           algorithm
//         );
//       }
//   }
//   throw Error('Unrecognized algorithm name');
// }

// Node's implementation is slightly different
// setting properties manually on the class
// going for something simpler for the moment
class SubtleCrypto {
  // encrypt(algorithm: string, key, data) {
  //   algorithm = webidl.converters.AlgorithmIdentifier(algorithm, {
  //     prefix,
  //     context: '1st argument',
  //   });
  //   key = webidl.converters.CryptoKey(key, {
  //     prefix,
  //     context: '2nd argument',
  //   });
  //   data = webidl.converters.BufferSource(data, {
  //     prefix,
  //     context: '3rd argument',
  //   });
  //   algorithm = normalizeAlgorithm(algorithm, 'encrypt');
  //   return cipherOrWrap(
  //     kWebCryptoCipherEncrypt,
  //     algorithm,
  //     key,
  //     data,
  //     'encrypt'
  //   );
  // }

  async generateKey(
    algorithm: {
      name: string;
      length: number;
    },
    extractable: boolean,
    keyUsages: Array<'encrypt' | 'decrypt'>
  ) {
    // webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'generateKey' on 'SubtleCrypto'";
    // webidl.requiredArguments(arguments.length, 3, { prefix });
    // algorithm = webidl.converters.AlgorithmIdentifier(algorithm, {
    //   prefix,
    //   context: '1st argument',
    // });
    // extractable = webidl.converters.boolean(extractable, {
    //   prefix,
    //   context: '2nd argument',
    // });
    // keyUsages = webidl.converters['sequence<KeyUsage>'](keyUsages, {
    //   prefix,
    //   context: '3rd argument',
    // });

    // normalizeAlgorithm does some weird shit comparing keys with the desired function
    // it shorthands though, so it seems all we care about is the name
    // algorithm = normalizeAlgorithm(algorithm, 'generateKey');
    let result;
    let resultType;
    switch (algorithm.name) {
      case 'RSASSA-PKCS1-v1_5':
      // Fall through
      case 'RSA-PSS':
      // Fall through
      case 'RSA-OAEP':
        resultType = 'CryptoKeyPair';
        result = await require('internal/crypto/rsa').rsaKeyGenerate(
          algorithm,
          extractable,
          keyUsages
        );
        break;
      case 'Ed25519':
      // Fall through
      case 'Ed448':
      // Fall through
      case 'X25519':
      // Fall through
      case 'X448':
        // resultType = 'CryptoKeyPair';
        // result = await require('internal/crypto/cfrg')
        //   .cfrgGenerateKey(algorithm, extractable, keyUsages);
        break;
      case 'ECDSA':
      // Fall through
      case 'ECDH':
        // resultType = 'CryptoKeyPair';
        // result = await require('internal/crypto/ec')
        //   .ecGenerateKey(algorithm, extractable, keyUsages);
        break;
      case 'HMAC':
        // resultType = 'CryptoKey';
        // result = await require('internal/crypto/mac')
        //   .hmacGenerateKey(algorithm, extractable, keyUsages);
        break;
      case 'AES-CTR':
      // Fall through
      case 'AES-CBC':
      // Fall through
      case 'AES-GCM':
      // Fall through
      case 'AES-KW':
        resultType = 'CryptoKey';
        result = await require('internal/crypto/aes').aesGenerateKey(
          algorithm,
          extractable,
          keyUsages
        );
        break;
      default:
        throw new Error('Unrecognized algorithm name');
    }

    if (
      (resultType === 'CryptoKey' &&
        (result.type === 'secret' || result.type === 'private') &&
        result.usages.length === 0) ||
      (resultType === 'CryptoKeyPair' && result.privateKey.usages.length === 0)
    ) {
      throw new Error('Usages cannot be empty when creating a key.');
    }

    return result;
  }
}

export const subtle = new SubtleCrypto();
