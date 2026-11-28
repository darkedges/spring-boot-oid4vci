import {spawnSync,spawn} from 'node:child_process';
import {existsSync,mkdirSync,readFileSync,writeFileSync,openSync,copyFileSync,rmSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {randomBytes} from 'node:crypto';
import {generateKeyPair,exportJWK} from 'jose';
import {BANK,ISSUER,VERIFIER,AUTHSTACK,BANK_ISSUER,ENVIRONMENT,PROXY_ROOT,demoFetch} from './hosts.mjs';
import {seed} from './seed.mjs';
const dir=import.meta.dirname,root=resolve(dir,'../../..');
process.chdir(dir);mkdirSync('runtime/keys',{recursive:true});mkdirSync('artifacts',{recursive:true});
// Secrets of this demo only, made once and kept under the ignored runtime folder.
const secret=name=>{const file=resolve(dir,'runtime/'+name);if(!existsSync(file))writeFileSync(file,randomBytes(32).toString('hex'),{mode:0o600});return readFileSync(file,'utf8').trim();};
const env={...process.env,SHOWCASE_CALLBACK_SECRET:secret('callback-secret'),DEMO_WORKER_SECRET:secret('worker-secret'),DEMO_ADMIN_TOKEN:secret('admin-token')};
if(!env.JAVA_HOME&&existsSync('C:/development/utils/java/jdk25.0.18'))env.JAVA_HOME='C:/development/utils/java/jdk25.0.18';
const priorPath=env.PATH||env.Path||'';delete env.Path;delete env.PATH;env.PATH=[dirname(process.execPath),resolve(root,'.cache/npm-runner/package/bin'),env.JAVA_HOME?env.JAVA_HOME+'/bin':'',priorPath].filter(Boolean).join(process.platform==='win32'?';':':');
const run=(cmd,args,cwd=dir)=>{if(cmd==='mvn'&&existsSync('C:/ProgramData/chocolatey/lib/maven/apache-maven-3.8.6/bin/mvn.cmd'))cmd='C:/ProgramData/chocolatey/lib/maven/apache-maven-3.8.6/bin/mvn.cmd';const result=spawnSync(cmd,args,{cwd,env,stdio:'inherit',shell:process.platform==='win32',windowsHide:true});if(result.status!==0)throw Error(cmd+' failed');};
const compose=args=>run('docker',['compose','-p','risk-e-onboarding-showcase','-f',resolve(dir,'compose.yml'),...args]);
const settings={adminToken:env.DEMO_ADMIN_TOKEN,clientId:'demo-bank-worker'};
async function ready(urls){for(const url of urls){const request=url.startsWith('https:')?demoFetch(url,{timeout:3000}):fetch(url,{signal:AbortSignal.timeout(3000)});const r=await request;if(!r.ok)throw Error('Not ready: '+url);console.log('Ready: '+url);}}
const services=[ISSUER+'/.well-known/openid-credential-issuer',VERIFIER+'/',AUTHSTACK+'/'+ENVIRONMENT+'/as/jwks',BANK+'/','http://localhost:43180/realms/risk-e-demo','http://localhost:43126/api/v1/messages'];
const check=()=>ready([...services,ISSUER+'/.well-known/openid-credential-issuer/t/bank',BANK_ISSUER+'/jwks','http://localhost:43100/','http://localhost:43101/']);
async function eventually(step,failure){let last;for(let i=0;i<90;i++){try{await step();return;}catch(error){last=error;await new Promise(r=>setTimeout(r,2000));}}throw Error(failure+': '+last?.message);}
const keytool=()=>env.JAVA_HOME?env.JAVA_HOME+'/bin/keytool':'keytool';
/** The keytool call without a shell, so names with spaces and punctuation arrive whole. */
function key(args){const result=spawnSync(keytool(),args,{cwd:dir,env,encoding:'utf8',windowsHide:true});if(result.status!==0)throw Error('keytool failed: '+result.stdout+result.stderr);return result.stdout;}
/** The CA that certifies the demo tenants' keys, which the demo wallet build is told to trust. */
function tenantCa(){
 mkdirSync('runtime/tenant-ca',{recursive:true});const store='runtime/tenant-ca/ca.p12';
 if(!existsSync(store))key(['-genkeypair','-alias','demo-tenant-ca','-keyalg','EC','-groupname','secp256r1','-dname','CN=Risk E Demo Tenant CA','-validity','730','-ext','BC:critical=ca:true','-ext','KU:critical=keyCertSign,cRLSign','-storetype','PKCS12','-keystore',store,'-storepass','showcase-local-only']);
 key(['-exportcert','-rfc','-alias','demo-tenant-ca','-keystore',store,'-storepass','showcase-local-only','-file','runtime/tenant-ca/ca.pem']);
}
/** Starts the proxy, then lets the demo's Java services trust the certificate authority it made. */
async function proxy(){
 mkdirSync('runtime/caddy',{recursive:true});compose(['up','-d','proxy']);
 await eventually(async()=>{if(!existsSync(PROXY_ROOT))throw Error('no root certificate yet');},'The demo proxy made no certificate');
 if(!env.JAVA_HOME)throw Error('Set JAVA_HOME to a JDK 21+');
 mkdirSync('runtime/trust',{recursive:true});const store='runtime/trust/truststore.p12';rmSync(store,{force:true});copyFileSync(resolve(env.JAVA_HOME,'lib/security/cacerts'),store);
 key(['-importcert','-noprompt','-alias','demo-proxy','-file',PROXY_ROOT,'-keystore',store,'-storepass','changeit']);
}
/** Containers up, the bank set up on the shared services, everything answering. */
async function start(){
 await proxy();compose(['up','-d','--remove-orphans']);
 await eventually(()=>ready(services),'Demo did not become healthy');await seed(settings);
}
function helper(){
 return fetch('http://localhost:43100/').then(r=>r.ok,()=>false).then(running=>{if(running)return;const log=openSync('artifacts/server.log','a');const child=spawn(process.execPath,[resolve(dir,'server.mjs')],{cwd:dir,env,detached:true,windowsHide:true,stdio:['ignore',log,log]});child.unref();writeFileSync('runtime/server.pid',String(child.pid));});
}
async function build(){
 for(const name of ['passport','bank'])if(!existsSync('runtime/keys/'+name+'.jwk')){const keys=await generateKeyPair('ES256',{extractable:true});const jwk={...await exportJWK(keys.privateKey),kid:name==='bank'?'bank-staff-1':'showcase-'+name};writeFileSync('runtime/keys/'+name+'.jwk',JSON.stringify(jwk),{mode:0o600});writeFileSync('runtime/keys/'+name+'-public.jwk',JSON.stringify({...await exportJWK(keys.publicKey),kid:jwk.kid}));}
 const repository='-Dmaven.repo.local='+resolve(root,'.m2/repository');
 run('mvn',['-f',resolve(root,'oid4vp/pom.xml'),'clean','install','-DskipTests',repository]);
 run('mvn',['-f',resolve(root,'oid4vci/pom.xml'),'-pl','bank-onboarding,oid4vci-demo-issuer','-am','package','-DskipTests','-Dbank.build.directory='+resolve(dir,'runtime/bank-target'),repository]);
 mkdirSync('runtime/jars',{recursive:true});
 for(const [from,to] of [[resolve(dir,'runtime/bank-target/bank-onboarding-0.1.0-SNAPSHOT.jar'),'bank'],[resolve(root,'oid4vci/oid4vci-demo-issuer/target/oid4vci-demo-issuer.jar'),'issuer'],[resolve(root,'oid4vp/oid4vp-demo-verifier/target/oid4vp-demo-verifier.jar'),'verifier']])copyFileSync(from,'runtime/jars/'+to+'.jar');
 run('npx',['ng','build','--configuration','showcase'],resolve(root,'oid4vci-wallet'));
 run('npm',['run','build:plugins'],resolve(root,'identityproofing'));
 run('npx',['vite','build','--mode','showcase','--outDir','dist-showcase'],resolve(root,'identityproofing/app'));
}
async function stopHelper(){try{await fetch('http://localhost:43100/bridge/shutdown',{method:'POST',headers:{'X-Demo-Secret':env.SHOWCASE_CALLBACK_SECRET}});}catch{}}
async function up(){
 await stopHelper();compose(['down']);await build();tenantCa();await start();await helper();
 await eventually(check,'Demo did not become healthy');
}
async function reset(){tenantCa();compose(['down','-v']);await start();await helper();await eventually(check,'Demo reset did not become healthy');}
const task=process.argv[2]||'check';
if(task==='up')await up();
else if(task==='check')await check();
else if(task==='down'){await stopHelper();compose(['down']);}
else if(task==='reset')await reset();
else if(task==='voiceover')run('docker',['compose','-p','risk-e-onboarding-showcase-tools','-f','tools.yml','run','--rm','voiceover']);
else if(task==='demo'){await up();await reset();run(process.execPath,['control.mjs','voiceover']);run(process.execPath,['record.mjs']);}
else throw Error('Unknown demo command');
