import io,zipfile,os,tempfile
os.environ['CIPHERSETU_DB']=tempfile.mktemp()
from fastapi.testclient import TestClient
from backend.main import app
from backend.scanner import scan
c=TestClient(app)
def archive(name,text):
 b=io.BytesIO()
 with zipfile.ZipFile(b,'w') as z:z.writestr(name,text)
 return b.getvalue()
def test_demo_persistence():
 r=c.post('/api/demo');assert r.status_code==200
 d=r.json();assert d['counts']['H']==1;assert c.get('/api/scans/'+d['id']).json()==d
 assert all('Unknown' in f['break_time'] for f in d['findings'])
def test_zip():
 r=c.post('/api/scan/zip',files={'file':('r.zip',archive('a.py','RSA.generate(2048)'))});assert r.status_code==200
 assert r.json()['findings'][0]['severity']=='H'
def test_paths_and_origin():
 assert c.post('/api/scan/zip',files={'file':('r.zip',archive('../bad','RSA'))}).status_code==400
 assert c.post('/api/demo',headers={'Origin':'https://evil.example'}).status_code==403
 assert c.post('/api/scan/github',data={'repo':'http://127.0.0.1'}).status_code==400
def test_comments_and_no_false_assurance():
 r=scan(archive('a.py','# RSA\nprint("hello")'));assert not r['findings'];assert 'No findings' in r['coverage']['limitations']
def test_hybrid():
 r=scan(archive('a.go','X25519MLKEM768 X25519'));assert r['findings'][0]['severity']=='L'
