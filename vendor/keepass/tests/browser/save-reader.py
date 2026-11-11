"""Read the five public browser outputs with an independent KeePassXC CLI."""
import hashlib,json,struct,subprocess,tempfile,sys,xml.etree.ElementTree as ET
from pathlib import Path
base=Path(sys.argv[1]).resolve()
fixtures=base/'fixtures'
cli=Path(sys.argv[2]).resolve()
expected=bytes(i%251 for i in range(200_003))
results=[]
with tempfile.TemporaryDirectory(prefix='read-',dir=base) as scratch:
 scratch=Path(scratch)
 for name,password,keyfile in [('password',b'PUBLIC-KDBX-EXPORT',False),('keyfile',None,True),('both',b'PUBLIC-KDBX-EXPORT',True),('empty-password',b'',False),('empty-both',b'',True)]:
  db=fixtures/(name+'.kdbx')
  data=db.read_bytes();at=12
  while True:
   tag=data[at];size=struct.unpack_from('<I',data,at+1)[0];at+=5+size
   if tag==0:break
  at+=64;sizes=[]
  while True:
   size=struct.unpack_from('<I',data,at+32)[0];sizes.append(size);at+=36+size
   if size==0:break
  assert at==len(data) and max(sizes)<=65_536 and len(sizes)>=4,sizes
  flags=['-q']+(['--no-password'] if password is None else [])+(['-k',str(fixtures/'public.key')] if keyfile else [])
  secret=b'' if password is None else password+b'\n'
  def run(command,arguments=(),stdin=secret,extra_flags=()):
   return subprocess.run([str(cli),command,*flags,*extra_flags,str(db),*arguments],input=stdin,capture_output=True,timeout=30)
  shown=run('show',['Public'],extra_flags=['-s','-a','Password'])
  assert shown.returncode==0,(name,shown.stderr)
  assert shown.stdout=='PUBLIC-CURRENT\r\n秘密\n'.encode(),(name,shown.stdout)
  exported=run('export');assert exported.returncode==0,(name,exported.stderr)
  root=ET.fromstring(exported.stdout)
  fields={field.findtext('Key'):field.find('Value') for field in root.findall('.//Entry/String')}
  assert fields['Password'].get('ProtectInMemory')=='True'
  assert fields['UserName'].get('ProtectInMemory','False')=='False'
  assert fields['Private'].get('ProtectInMemory')=='True' and fields['Private'].text=='PUBLIC-NOTE'
  assert fields['Empty'].get('ProtectInMemory')=='True' and fields['Empty'].text in (None,'')
  for filename,payload in [('public.bin',expected),('empty.bin',b'')]:
   target=scratch/(name+'-'+filename)
   output=run('attachment-export',['Public',filename,str(target)])
   assert output.returncode==0,(name,output.stderr)
   assert target.read_bytes()==payload
  if password is not None:
   wrong=run('show',['Public'],stdin=b'PUBLIC-WRONG\n')
   assert wrong.returncode!=0 and b'PUBLIC-CURRENT' not in wrong.stdout
  corrupt=scratch/(name+'-corrupt.kdbx');broken=bytearray(data);broken[-36]^=1;corrupt.write_bytes(broken)
  corrupted=subprocess.run([str(cli),'show',*flags,str(corrupt),'Public'],input=secret,capture_output=True,timeout=30)
  assert corrupted.returncode!=0 and b'PUBLIC-CURRENT' not in corrupted.stdout
  wrong_key_rejected=None
  if keyfile:
   wrong_key=scratch/(name+'-wrong.key');wrong_key.write_bytes(bytes([8])*32)
   wrong_flags=['-q']+(['--no-password'] if password is None else [])+['-k',str(wrong_key)]
   wrong=subprocess.run([str(cli),'show',*wrong_flags,str(db),'Public'],input=secret,capture_output=True,timeout=30)
   assert wrong.returncode!=0 and b'PUBLIC-CURRENT' not in wrong.stdout
   wrong_key_rejected=True
  results.append({'mode':name,'bytes':len(data),'frames':sizes,'passwordCRExact':True,'protectedFlag':True,'twoExactAttachments':True,'terminalMacTamperRejected':True,'wrongKeyfileRejected':wrong_key_rejected})
print(json.dumps({'consumer':subprocess.check_output([str(cli),'--version'],text=True).strip(),'consumerSha256':hashlib.sha256(cli.read_bytes()).hexdigest(),'results':results},ensure_ascii=False))
