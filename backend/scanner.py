import io,zipfile,re,hashlib
SOURCE='https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs'
RULES=[
 ('RSA',r'\bRSA\b|rsa[._]',7,'Shor: factoring threatens RSA encryption/key wrapping and signatures.','For key establishment assess ML-KEM-based protocols; for signatures assess ML-DSA/SLH-DSA. Confirm the actual use first.'),
 ('ECC',r'\bECDSA\b|\bECDH\b|\bX25519\b|\bEd25519\b',7,'Shor: discrete logarithms threaten standalone classical elliptic-curve schemes.','Assess ML-KEM for key establishment or ML-DSA/SLH-DSA for signatures; check whether already part of a hybrid.'),
 ('DES/RC4',r'\bDES\b|\bRC4\b|\bARC4\b',9,'Already weak classically; quantum computing is not required.','Replace with an appropriate authenticated encryption construction such as AES-256-GCM.'),
 ('MD5/SHA1',r'\bmd5\s*\(|\bsha1\s*\(|\bMD5\b|\bSHA-1\b',6,'Classical collision weaknesses; not evidence that passwords or arbitrary hashes can be decrypted.','Review usage: replace collision-sensitive hashing/signatures; use a password KDF for passwords.'),
 ('AES-128',r'AES[-_]128|aes-128',4,'Grover gives an idealized quadratic key-search speedup; not a practical break-time estimate.','Review confidentiality lifetime; consider AES-256 for new designs. AES-128 detection alone is not a demonstrated vulnerability.'),
 ('AES-256',r'AES[-_]256|aes-256',1,'Generic Grover search; AES-256 remains a strong choice under current knowledge.','Retain if correctly implemented; inspect mode, nonce handling and key protection separately.'),
 ('PQC',r'\bML[-_]?KEM\b|\bML[-_]?DSA\b|\bSLH[-_]?DSA\b',1,'No known Shor-style break of these standardized PQ families.','Verify parameters, library version, protocol composition and key custody; a name match is not proof of safety.')]
def scan(data,years=0):
 findings=[];skipped=[];count=0;total=0
 with zipfile.ZipFile(io.BytesIO(data)) as z:
  if len(z.infolist())>3000:raise ValueError('Archive exceeds 3000 entries')
  for f in z.infolist():
   if f.is_dir():continue
   if f.filename.startswith('/') or '..' in f.filename.split('/') or '\\' in f.filename:raise ValueError('Unsafe archive path')
   if (f.external_attr>>16)&0o170000==0o120000:skipped.append({'path':f.filename,'reason':'symlink'});continue
   total+=f.file_size
   if total>40*1024*1024:raise ValueError('Expanded archive exceeds 40 MiB')
   if f.file_size>1024*1024:skipped.append({'path':f.filename,'reason':'over 1 MiB'});continue
   b=z.read(f)
   try:text=b.decode('utf-8')
   except UnicodeDecodeError:skipped.append({'path':f.filename,'reason':'binary/unknown encryption'});continue
   if '\x00' in text:skipped.append({'path':f.filename,'reason':'binary'});continue
   count+=1
   for n,line in enumerate(text.splitlines(),1):
    if line.lstrip().startswith(('#','//','*')):continue
    for name,pattern,base,attack,advice in RULES:
     if not re.search(pattern,line,re.I):continue
     # Hybrid evidence avoids treating the classical component as standalone confirmed risk.
     hybrid=name=='ECC' and re.search(r'MLKEM|ML-KEM|XWing|X-Wing',line,re.I)
     score=3 if hybrid else min(10,base+(1 if years>=10 and name in ('RSA','ECC') else 0))
     severity='C' if score>=9 else 'H' if score>=7 else 'M' if score>=4 else 'L'
     findings.append(dict(path=f.filename,line=n,algorithm=name,score=score,severity=severity,confidence='low' if hybrid else 'medium',evidence='Matched cryptographic identifier; source omitted to avoid secret disclosure',quantum_attack=attack,break_time='Unknown: no validated hardware/resource model or arrival date. No wall-clock prediction.',recommendation=advice,reason=f'Policy baseline {base}; declared retention {years} years; hybrid adjustment {bool(hybrid)}. Candidate requires human review.',source=SOURCE,migration='Manual review; automatic migration only for CipherSetu envelopes, with owner keys.'))
     if len(findings)>=5000:raise ValueError('Too many findings; narrow repository')
 return dict(findings=findings,counts={s:sum(f['severity']==s for f in findings) for s in 'CHML'},coverage={'scanned_text_files':count,'skipped':skipped,'limitations':'Heuristic identifier scanner, not dataflow analysis. Does not prove runtime use, detect arbitrary ciphertext, scan history, submodules or deployed storage. No findings does not mean secure.'},sha256=hashlib.sha256(data).hexdigest(),retention_years=years,scoring='CipherSetu triage policy v1; not CVSS and not a quantum break probability.')
