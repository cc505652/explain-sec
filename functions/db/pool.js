const { Pool } = require("pg");
const { adminConfig, runtimeConfig } = require("./config");

let runtimePool;
let adminPool;

function getRuntimePool() {
  if (!runtimePool) runtimePool = new Pool(runtimeConfig());
  return runtimePool;
}

function getAdminPool() {
  if (!adminPool) adminPool = new Pool(adminConfig());
  return adminPool;
}

async function closePools() {
  await Promise.all([
    runtimePool ? runtimePool.end() : Promise.resolve(),
    adminPool ? adminPool.end() : Promise.resolve(),
  ]);
  runtimePool = undefined;
  adminPool = undefined;
}

module.exports = { getRuntimePool, getAdminPool, closePools };
