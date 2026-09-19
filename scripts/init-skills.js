#!/usr/bin/env node
import { cp, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
const dst=join(homedir(),".dsh","skills");
await mkdir(dst,{recursive:true});
await cp("./skills",dst,{recursive:true});
console.log(`✓ seeds copied to ${dst}`);
