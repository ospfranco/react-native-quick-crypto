import { kAesKeyLengths, validateInteger, type KAesKeyLength } from './Utils';

export async function generateKey(
  mode: string,
  type: string,
  options: { length: KAesKeyLength }
) {
  // validateString(keyType, 'type');
  // validateObject(options, 'options');
  const { length } = options;
  switch (type) {
    case 'hmac':
      validateInteger(length, 'options.length', 8, 2 ** 31 - 1);
      break;
    case 'aes':
      // validateOneOf(length, 'options.length', kAesKeyLengths);
      break;
    default:
      throw new Error(`type ${type} must be a supported key type`);
  }

  return new SecretKeyGenJob(mode, type, length);
}
