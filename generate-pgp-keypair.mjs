import * as openpgp from 'openpgp';
import fs from 'fs';
import path from 'path';
import { mkdirSync } from 'fs';

const outputDir = './test';
mkdirSync(outputDir, { recursive: true });

const generate = async () => {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'rsa',
    rsaBits: 2048,
    userIDs: [{ name: 'test2', email: 'test2@upgp.xyz' }],
    passphrase: '', // No passphrase
  });

  fs.writeFileSync(path.join(outputDir, 'test2-private-key.pem'), privateKey, 'utf-8');
  fs.writeFileSync(path.join(outputDir, 'test2-public-key.pem'), publicKey, 'utf-8');

  console.log('✅ Keys written to ./test/');
};

generate();
