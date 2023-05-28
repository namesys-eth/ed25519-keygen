import { deepStrictEqual } from 'assert';
import { should } from 'micro-should';
import * as ipns from '../ipns.js';
import { hex } from '@scure/base';

should('ipns: basic', async () => {
  const seed = hex.decode('0681d6420abb1ba47acd5c03c8e5ee84185a2673576b262e234e50c46d86f597');
  const pub = hex.decode('12c8299ec2c51dffbbcb4f9fccadcee1424cb237e9b30d3cd72d47c18103689d');
  const addr = 'bafzaajaiaejcaewifgpmfri57654wt47zsw45ykcjszdp2ntbu6nolkhygaqg2e5';
  deepStrictEqual(await ipns.getKeys(seed), {
    publicKey: '0x017200240801122012c8299ec2c51dffbbcb4f9fccadcee1424cb237e9b30d3cd72d47c18103689d',
    privateKey: '0x080112400681d6420abb1ba47acd5c03c8e5ee84185a2673576b262e234e50c46d86f59712c8299ec2c51dffbbcb4f9fccadcee1424cb237e9b30d3cd72d47c18103689d',
    base32: 'bafzaajaiaejcaewifgpmfri57654wt47zsw45ykcjszdp2ntbu6nolkhygaqg2e5',
    base16: 'f017200240801122012c8299ec2c51dffbbcb4f9fccadcee1424cb237e9b30d3cd72d47c18103689d',
    contenthash: '0xe501017200240801122012c8299ec2c51dffbbcb4f9fccadcee1424cb237e9b30d3cd72d47c18103689d'
  });
  const parsed = ipns.parseAddress(addr);
  deepStrictEqual(ipns.formatPublicKey(parsed), addr);
});
