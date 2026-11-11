// Read only the public test corpus with the pinned Bitwarden SDK and importer.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {environment}=require('../../import_fixtures/bitwarden_encrypted_json/capture.cjs');
const {loadImporter}=require('../bitwarden_json/reader.cjs');
const password=' Public export 密码 é e\u0301 ';
async function main() {
  const [cryptoSources,sdkPath,jsonSources,directory]=process.argv.slice(2);
  assert(cryptoSources&&sdkPath&&jsonSources&&directory,'Usage: reader.cjs CRYPTO_SOURCES SDK JSON_SOURCES PUBLIC_EXPORT_DIRECTORY');
  const {sdk,keys}=environment(cryptoSources,sdkPath);
  const Importer=loadImporter(jsonSources);
  const cases=[];
  for(const profile of ['personal','organization']) {
    const bytes=fs.readFileSync(path.join(directory,profile+'.json'));
    const doc=JSON.parse(bytes);
    assert.equal(doc.encrypted,true);assert.equal(doc.passwordProtected,true);
    assert.deepEqual([doc.kdfType,doc.kdfIterations,doc.kdfMemory,doc.kdfParallelism],[1,3,64,4]);
    assert.equal(Buffer.from(doc.salt,'base64').length,16);
    const config={toSdkConfig:()=>({argon2id:{iterations:doc.kdfIterations,memory:doc.kdfMemory,parallelism:doc.kdfParallelism}})};
    const key=(await keys.deriveVaultExportKey(password,doc.salt,config)).toEncoded();
    const clear=sdk.PureCrypto.symmetric_decrypt_string(doc.data,key);
    assert.match(sdk.PureCrypto.symmetric_decrypt_string(doc.encKeyValidation_DO_NOT_EDIT,key),/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
    const json=JSON.parse(clear);
    assert.equal(json.items.length,3);
    assert.equal(json.items[0].card.number,'4111111111111111');
    assert.equal(json.items[1].identity.email,'current@example.invalid');
    assert.equal(json.items[1].identity.phone,'');
    assert(!Object.hasOwn(json.items[1].identity,'passportNumber'));
    const login=json.items[2];
    assert.equal(login.login.username,'public-user');
    assert.equal(login.login.password,'PUBLIC-CURRENT\r\n第二行');
    assert.deepEqual(login.login.uris.map(u=>u.uri),['https://one.invalid/','https://two.invalid/?a=1&b=2']);
    assert.equal(login.login.totp,'otpauth://totp/Provider:public?secret=MZXW6YTBOI&issuer=Provider&algorithm=SHA256&digits=8&period=45');
    assert.equal(login.notes,'Public notes\r\n<&>');
    assert.deepEqual(login.fields.map(f=>[f.name,f.value,f.type]),[['','',0],['Same','line one\n"line two"\\公開',0],['Same','PUBLIC-HIDDEN',1]]);
    assert(!clear.includes('PUBLIC-OLD-ID')&&!clear.includes('old@example.invalid'));
    const importer=new Importer();importer.organizationId=profile==='organization'?'public-destination':null;
    const parsed=await importer.parse(clear);
    assert.equal(parsed.success,true);assert.equal(parsed.errors.length,0);assert.equal(parsed.ciphers.length,3);
    assert.equal(parsed.ciphers[2].login.password,'PUBLIC-CURRENT\r\n第二行');
    assert.equal(parsed.ciphers[2].fields[2].type,1);
    if(profile==='personal') {
      assert.deepEqual(Array.from(parsed.folders,f=>f.name),['Shared']);
    }else {
      assert.deepEqual(Array.from(parsed.collections,c=>c.name).sort(),['Second','Shared']);
    }
    for(const candidate of ['PUBLIC-WRONG',password.trim(),' Public export 密码 é é ']) {
      const wrong=(await keys.deriveVaultExportKey(candidate,doc.salt,config)).toEncoded();
      assert.throws(()=>sdk.PureCrypto.symmetric_decrypt_string(doc.data,wrong));
    }
    for(const field of ['data','encKeyValidation_DO_NOT_EDIT']) {
      const parts=doc[field].slice(2).split('|');
      for(let at=0;at<3;at++) {
        const changed=[...parts],value=Buffer.from(changed[at],'base64');value[0]^=1;changed[at]=value.toString('base64');
        assert.throws(()=>sdk.PureCrypto.symmetric_decrypt_string('2.'+changed.join('|'),key));
      }
    }
    cases.push({profile,bytes:bytes.length,currentValues:true,wrongPasswords:true,tamper:true,importer:true});
  }
  console.log(JSON.stringify({sdk:require(path.join(sdkPath,'package.json')).version,commit:fs.readFileSync(path.join(sdkPath,'VERSION'),'utf8').trim(),cases}));
}
main().catch(error=>{console.error(error);process.exitCode=1;});
