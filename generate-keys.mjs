import * as openpgp from 'openpgp';
import fs from 'fs';

const generate = async () => {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'rsa',
    rsaBits: 2048,
    userIDs: [{ name: 'upgp.xyz', email: 'admin@upgp.xyz' }],
    passphrase: '', // leave empty for now (you can add one later)
  });

  // Save to .env-safe format
  const env = [
    `upgpk=${JSON.stringify(publicKey)}`,
    `upgps=${JSON.stringify(privateKey)}`
  ].join('\n');

  fs.writeFileSync('./nothing.txt', env, { encoding: 'utf8' });

  console.log('✅ Keys generated and written to ./test/stuff.txt');
};

generate();
