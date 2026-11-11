// Run the source reader with public data and test view objects.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const fs = require('node:fs');
const {stripTypeScriptTypes} = require('node:module');
const path = require('node:path');
const vm = require('node:vm');

function loadContext(sourceDir) {
  const models = JSON.parse(fs.readFileSync(path.join(__dirname, '../../import_fixtures/bitwarden_json/capture-sources.json')));
  const reader = JSON.parse(fs.readFileSync(path.join(__dirname, 'reader-sources.json')));
  assert.equal(reader.commit, models.commit);
  class View { constructor(properties) { Object.assign(this, properties); } }
  class UnusedCrypto { constructor() { throw Error('The reader must not use encryption'); } }
  const globals = {EncString:UnusedCrypto, SymmetricCryptoKey:UnusedCrypto,
    ConsoleLogService:class {}, CipherRepromptType:{None:0}, SecureNoteType:{Generic:0}};
  for(const name of ['Folder','Field','LoginUri','Login','Fido2Credential','SecureNote','Card','Identity','SshKey','BankAccount','DriversLicense','Passport','PasswordHistory','Cipher','Collection']) {
    globals[name+'View'] = View;
  }
  const context = vm.createContext(globals);
  const files = [...models.files.filter(file=>!file.path.endsWith('/individual-vault-export.service.ts')), ...reader.files];
  for(const file of files) {
    const bytes = fs.readFileSync(path.join(sourceDir, file.local ?? path.basename(file.path)));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256, file.path);
    let text = bytes.toString('utf8');
    if(file.local === 'utils-platform.ts') {
      const begin=text.indexOf('  static isNullOrWhitespace(');
      const end=text.indexOf('\n  }',begin);
      assert(begin>=0 && end>begin);
      text='class Utils {\n'+text.slice(begin,end+4)+'\n}';
    }
    text=text.replace(/^import[\s\S]*?;\s*$/gm,'');
    const js=stripTypeScriptTypes(text).replace(/\bexport\s+(?=(?:class|function|const)\b)/g,'');
    vm.runInContext(js,context,{filename:file.path,timeout:1000});
  }
  return context;
}
function loadImporter(sourceDir) {
  return vm.runInContext('BitwardenJsonImporter',loadContext(sourceDir));
}

async function main() {
  const [sourceDir, personalFile, organizationFile] = process.argv.slice(2);
  assert(sourceDir && personalFile && organizationFile, 'Usage: reader.cjs SOURCE_DIRECTORY PERSONAL_JSON ORGANIZATION_JSON');
  const Importer=loadImporter(sourceDir);
  for(const [profile, filename] of [['personal',personalFile],['organization',organizationFile]]) {
    const importer=new Importer();
    importer.organizationId=profile==='organization'?'public-destination-organization':null;
    const result=await importer.parse(fs.readFileSync(filename,'utf8'));
    assert.equal(result.success,true);
    assert.equal(result.errors.length,0);
    assert.equal(result.ciphers.length,7);
    const [login,note,card,identity,blankNote,blankTitle,ssh]=result.ciphers;
    assert.deepEqual(Array.from(result.ciphers,c=>c.type),[1,2,3,4,2,2,5]);
    assert(result.ciphers.every(c=>c.id===null&&c.organizationId===null&&c.collectionIds===null&&c.key===null));
    assert.equal(login.login.username,'public-user');
    assert.equal(login.login.password,'PUBLIC-CURRENT-PASSWORD');
    assert.equal(login.favorite,true);
    assert.equal(login.reprompt,1);
    assert.deepEqual(Array.from(login.login.uris,u=>u.uri),['https://one.invalid/','https://two.invalid/path?q=1&v=2']);
    assert.deepEqual(Array.from(login.login.uris,u=>u.match),[5,3]);
    assert.equal(login.login.totp,'otpauth://totp/Confidex?secret=MY&algorithm=SHA256&digits=8&period=45');
    assert.equal(login.notes,'Public notes');
    assert.deepEqual(Array.from(note.fields,f=>[f.name,f.value,f.type]),[
      ['','',0],['Same','line one\n"line two"\\公開',0],['Same','PUBLIC-HIDDEN',1],['Checkbox','false',2]]);
    assert.equal(note.fields[3].linkedId,null);
    assert.equal(card.card.number,'4111111111111111');
    assert.equal(card.card.cardholderName,'Public Holder');
    assert.equal(card.card.expMonth,'04');
    assert.equal(card.card.expYear,'2030');
    assert.equal(card.card.code,'123');
    assert.equal(identity.identity.email,'current@example.invalid');
    assert.equal(identity.identity.phone,'');
    assert.equal(identity.identity.passportNumber,undefined);
    assert.equal(blankNote.notes,null);
    assert.equal(blankNote.fields[0].value,'\ufeff');
    assert.equal(blankNote.fields[0].type,1);
    assert.equal(blankTitle.name,'--');
    assert(ssh.sshKey.privateKey.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----\n'));
    assert(ssh.sshKey.publicKey.startsWith('ssh-ed25519 '));
    assert(ssh.sshKey.keyFingerprint.startsWith('SHA256:'));
    if(profile==='personal') {
      assert.deepEqual(Array.from(result.folders,g=>g.name),['Shared']);
      assert.equal(result.collections.length,0);
      assert.deepEqual(Array.from(result.folderRelationships,p=>Array.from(p)),[[0,0],[1,0],[2,0]]);
    } else {
      assert.deepEqual(Array.from(result.collections,g=>g.name).sort(),['Second','Shared']);
      assert.equal(result.folders.length,0);
      assert.deepEqual(Array.from(result.collectionRelationships,p=>[p[0],result.collections[p[1]].name]),[[0,'Shared'],[0,'Second'],[1,'Shared'],[2,'Shared']]);
    }
    await assert.rejects(importer.parse('{"encrypted":true,"items":[]}'),/encrypted/i);
    assert.equal((await importer.parse('null')).success,false);
  }
  console.log('Pinned Bitwarden reader: 2 profiles, 7 items each, PASS');
}
module.exports = {loadContext, loadImporter};
if (require.main === module) main().catch(error=>{console.error(error);process.exitCode=1;});
