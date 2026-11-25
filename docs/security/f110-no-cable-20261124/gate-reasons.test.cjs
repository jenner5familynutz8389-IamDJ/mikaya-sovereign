'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),m=require('./metrics.cjs');
test('holds name actual causes without weakening the policy',()=>{
 assert.deepEqual(m.gateReasons({thermalSeverity:0,batteryPct:80,storageUsePct:98}),['STORAGE_HIGH']);
 assert.deepEqual(m.gateReasons({thermalSeverity:3,batteryPct:14,storageUsePct:99,batteryTempDeciC:451}),['THERMAL_HOLD','BATTERY_LOW','STORAGE_HIGH','BATTERY_TEMP_HIGH']);
 assert.deepEqual(m.gateReasons({thermalSeverity:null,batteryPct:null,storageUsePct:null}),['THERMAL_UNAVAILABLE','BATTERY_UNAVAILABLE','STORAGE_UNAVAILABLE']);
 assert.equal(m.gate({thermalSeverity:0,batteryPct:80,storageUsePct:97}),'ALLOW');
 assert.equal(m.gate({thermalSeverity:0,batteryPct:80,storageUsePct:98}),'HOLD');
});
