const test=require('node:test'),assert=require('node:assert/strict');
const {governedSyncMs}=require('../ahava/sync');
test('fresh thermal cadence bounded; stale or malformed conservative',()=>{
 const now=Date.now(),at=new Date(now).toISOString();
 assert.equal(governedSyncMs({at,syncMs:120000},now),120000);
 assert.equal(governedSyncMs({at,syncMs:1000},now),60000);
 assert.equal(governedSyncMs({at,syncMs:999999},now),600000);
 assert.equal(governedSyncMs({at:new Date(now-181000).toISOString(),syncMs:60000},now),180000);
 assert.equal(governedSyncMs({at:'bad',syncMs:60000},now),180000);
 assert.equal(governedSyncMs(null,now),180000);
});
