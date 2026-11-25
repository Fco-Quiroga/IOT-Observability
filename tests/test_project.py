import copy,json,shutil
from pathlib import Path
import pytest,yaml
from app.inventory import normalize,load,dump,coord,mac,endpoint
from app import topology,activegate,lookup
from app.dynatrace_client import Client
ROOT=Path(__file__).resolve().parents[1]
@pytest.fixture
def fixture(tmp_path):
    for k in ('cameras','branches','zones'): shutil.copy(ROOT/'data'/f'{k}.example.json',tmp_path/f'{k}.json')
    return tmp_path

def run(p): return normalize(p,p/'registry.json',ROOT/'config/inventory_aliases.yaml',True)
def change(p,k,fn):
    f=p/(k+'.json'); a=load(f); fn(a); dump(f,a)
def test_load(fixture):
    s,r,a=run(fixture); assert r['snmp_enabled']==2 and r['device_types']=={'IP_CAMERA':1,'NVR':1}; assert s['devices'][0]['criticality'] is None
    assert len(topology.build(s))==4

def test_descriptive_changes(fixture):
    s,r,_=run(fixture); old=topology.build(s); m=lookup.export(s,fixture/'old',report=r)
    change(fixture,'cameras',lambda a:a[0].update(ip='192.0.2.99',mac='02:00:00:00:00:99',model='NEW',criticality='HIGH',name='NEW'))
    change(fixture,'branches',lambda a:a[0].update(latitude=-34,longitude=-71,address='New address'))
    s,r,_=run(fixture); assert topology.build(s)==old
    n=lookup.export(s,fixture/'new',report=r); assert n['files'][0]['sha256']!=m['files'][0]['sha256']

def test_zone_move(fixture):
    s,_,_=run(fixture); old=topology.build(s)
    change(fixture,'zones',lambda a:a.append({'branch_id':'BRANCH-001','zone_id':'ZONE-002','zone_name':'New'}))
    change(fixture,'cameras',lambda a:a[0].update(zone_id='ZONE-002'))
    s,_,_=run(fixture); diff=topology.diff(old,topology.build(s)); assert len(diff['added'])==1 and len(diff['changed'])==1 and not diff['removed']

def test_bad_ip(fixture):
    change(fixture,'cameras',lambda a:a[0].update(ip='invalid'))
    s,r,_=run(fixture); assert len(s['devices'])==2 and r['snmp_enabled']==1

def test_excluded_branch(fixture):
    change(fixture,'branches',lambda a:a[0].update(latitude=None))
    s,r,_=run(fixture); assert not s['devices'] and not s['zones']

def test_orphan_zone(fixture):
    change(fixture,'cameras',lambda a:a[0].update(zone_id='missing'))
    s,r,_=run(fixture); assert len(s['devices'])==1 and r['audit_counts']['excluded_device_zone']==1

def test_provisional(fixture):
    change(fixture,'cameras',lambda a:a[1].update(ci_id=a[0]['ci_id']))
    s,r,_=run(fixture); assert r['provisional']==2 and len({d['ci_id'] for d in s['devices']})==2
    old=topology.build(s); change(fixture,'cameras',lambda a:a[0].update(ip='192.0.2.55')); s,_,_=run(fixture); assert topology.build(s)==old

def test_duplicate_mac(fixture):
    change(fixture,'cameras',lambda a:a[1].update(mac=a[0]['mac']))
    s,r,_=run(fixture); assert r['audit_counts']['invalid_or_duplicate_mac']==2

def test_nvr(fixture):
    change(fixture,'cameras',lambda a:a[1].update(device_type='IP_CAMERA'))
    s,r,_=run(fixture); assert r['device_types']['NVR']==1

def test_batches(fixture):
    s,_,_=run(fixture); cs=activegate.build(s,size=1,branch_routes={'BRANCH-001':'NORTH'}); assert len(cs)==2 and cs[0]['scope']=='ag_group-NORTH'; assert all(not c['value']['enabled'] for c in cs)
    assert activegate.SECRET in json.dumps(cs)
    with pytest.raises(ValueError): activegate.build(s,size=200)
    with pytest.raises(ValueError): activegate.build(s,features=['traffic','traffic32'])

def test_plan(fixture):
    s,_,_=run(fixture); cs=activegate.build(s); ex=copy.deepcopy(cs[0]); ex['objectId']='1'; ex['value']['snmp']['devices'][0]['authentication']['community']='MASKED'; assert activegate.plan(cs,[ex])[0][0]=='SKIP'
    ex['value']['description']='Other project'; assert activegate.plan(cs,[ex])[0][0]=='BLOCK'

def test_topology(fixture):
    s,_,_=run(fixture); es=topology.build(s); assert len(list(topology.batches(es,max_events=1)))==4
    with pytest.raises(ValueError): list(topology.batches(es,max_bytes=1))
    s['devices'][0]['zone_id']='orphan'
    with pytest.raises(ValueError): topology.build(s)

def test_lookup(fixture):
    s,r,_=run(fixture); m=lookup.export(s,fixture/'out',pilot=True,report=r); assert all('/piloto/' in f['filePath'] for f in m['files'])
    rows=[json.loads(l) for l in (fixture/'out/iot_devices.jsonl').read_text().splitlines()]; assert rows[0]['criticality'] is None and isinstance(rows[0]['latitude'],float)

def test_extension():
    y=yaml.safe_load((ROOT/'extension.yaml').read_text()); required=[m for g in y['snmp'] for sub in g['subgroups'] if 'featureSet' not in sub for m in sub['metrics']]; assert len(required)==1 and required[0]['value']=='oid:1.3.6.1.2.1.1.3.0'; assert y['snmp'][0]['interval']['minutes']==1

def test_http(monkeypatch):
    c=Client('https://example.invalid','fake-token')
    class R: status_code=403
    monkeypatch.setattr(c.session,'request',lambda *a,**k:R())
    with pytest.raises(RuntimeError,match='403'): c.request('GET','/test')

def test_coords():
    assert coord(-335000000,'lat',True)==-33.5; assert coord(-335000000,'lat',False) is None; assert mac('02-00-00-00-00-01')=='02:00:00:00:00:01'; assert endpoint('2001:db8::1',161)=='[2001:db8::1]:161'

def test_upload_refuses_empty_and_tampering(fixture):
    from app.cli import main
    s,r,_=run(fixture); out=fixture/'out'; lookup.export(s,out,report=r)
    main(['upload','--out',str(out)])
    with (out/'iot_devices.jsonl').open('a') as f: f.write('{}\n')
    with pytest.raises(SystemExit): main(['upload','--out',str(out)])
    s['devices']=[]; lookup.export(s,out,report=r)
    with pytest.raises(SystemExit): main(['upload','--out',str(out)])

def test_upload_rejects_pilot_prod_path(fixture):
    from app.cli import main
    s,r,_=run(fixture); out=fixture/'out'; m=lookup.export(s,out,pilot=True,report=r)
    m['files'][0]['filePath']='/lookups/iot/iot_devices'; dump(out/'lookup_manifest.json',m)
    with pytest.raises(SystemExit): main(['upload','--out',str(out)])

def test_ambiguous_endpoint(fixture):
    change(fixture,'cameras',lambda a:a[1].update(ip=a[0]['ip']))
    s,r,_=run(fixture); assert len(s['devices'])==2 and not any(d['snmp_enabled'] for d in s['devices'])

def test_ambiguous_branch(fixture):
    change(fixture,'branches',lambda a:a.append({**a[0],'branch_id':'BRANCH-002','name':'sUcUrSaL Démo','address':'Other location'}))
    change(fixture,'cameras',lambda a:a[0].update(branch_id=None,branch_name='Sucursal Demo'))
    s,r,_=run(fixture); assert len(s['branches'])==2 and r['audit_counts']['ambiguous_branch_name']==1 and len(s['devices'])==1

def test_pagination(monkeypatch):
    c=Client('https://example.invalid','fake-token'); calls=[]
    class R:
        def __init__(self,p): self.p=p
        def json(self): return self.p
    def req(method,path,**kw):
        calls.append(kw['params']); return R({'items':[{'objectId':str(len(calls))}],'nextPageKey':'next' if len(calls)==1 else None})
    monkeypatch.setattr(c,'request',req); assert len(c.configurations('/test'))==2; assert calls==[{}, {'page-key':'next'}]

def test_platform_config_write(monkeypatch):
    c=Client('https://example.invalid','fake-token','bearer')
    calls=[]
    class R:
        def __init__(self,code): self.status_code=code
        def json(self): return {'code':self.status_code,'objectId':'id1'}
    def req(method,path,**kw):
        calls.append((method,path,kw['json']))
        return R(201 if method=='POST' else 200)
    monkeypatch.setattr(c,'request',req)
    conf={'scope':'ag_group-SNMP','value':{'enabled':False}}
    assert c.create_configuration('/config',conf)=='id1'
    c.update_configuration('/config/id1',{'enabled':True},'id1')
    assert calls==[('POST','/config',conf),('PUT','/config/id1',{'value':{'enabled':True}})]
    assert c.session.headers['Authorization']=='Bearer fake-token'

def test_platform_incomplete_pagination(monkeypatch):
    c=Client('https://example.invalid','fake-token','bearer')
    class R:
        def json(self): return {'items':[], 'totalCount':2}
    monkeypatch.setattr(c,'request',lambda *a,**kw:R())
    with pytest.raises(RuntimeError,match='Incomplete'): c.configurations('/config')

def test_platform_configure_uses_apps(fixture, monkeypatch):
    from app import cli
    s,_,_=run(fixture)
    monkeypatch.setenv('DT_APPS_URL','https://apps.example.invalid')
    monkeypatch.setenv('DT_ENV_URL','https://live.example.invalid')
    monkeypatch.setenv('DT_PLATFORM_TOKEN','fake-token')
    calls=[]
    class FakeClient:
        def __init__(self,url,token,auth): calls.append((url,token,auth))
        def configurations(self,path): calls.append(path); return []
    monkeypatch.setattr(cli,'Client',FakeClient)
    a=cli.parser().parse_args(['configure','--out',str(fixture),'--check-access','--full'])
    cli.configure(a,s,False)
    assert calls==[('https://apps.example.invalid','fake-token','bearer'),'/platform/extensions/v2/extensions/custom:bank-iot-snmp/monitoring-configurations']
