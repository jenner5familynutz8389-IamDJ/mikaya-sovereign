'use strict';
/** MIKAYA strict owner-signed source verification.
 * Historical signed manifests may be authentic but incomplete/stale.
 * This command never grants OEM, wallet, ACT or government production authority.
 */
const path=require('node:path'),{verifyRelease}=require('./tools/verify-release-closure.cjs');
try{
 const args=process.argv.slice(2),root=path.resolve(args.find(x=>!x.startsWith('--'))||__dirname);
 const result=verifyRelease({root,requireComplete:args.includes('--require-complete')});
 console.log(JSON.stringify(result));
 if(!result.complete)process.exitCode=2;
}catch(error){
 console.error('MIKAYA_RELEASE_HOLD:',error.code||error.message);
 process.exitCode=2;
}
