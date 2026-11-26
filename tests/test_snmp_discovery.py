import json
from app.snmp_discovery import load_inventory,sample,matrix,group,result
def test_sample_and_coverage(tmp_path):
    rows=[{'ip':f'192.0.2.{i}','device_type':'IP_CAMERA','model':'Q','branch_id':str(i%2),'snmp_enabled':True} for i in range(1,7)]
    p=tmp_path/'devices.json';p.write_text(json.dumps({'devices':rows}))
    ds,skips=load_inventory(p);selected=sample(ds,3,'test')
    assert len(ds)==6 and len(selected)==3
    assert len({d['branch_id'] for d in selected})==2
    assert selected==sample(ds,3,'test')
    obs=[{**d,'checks':{'video_ch01':result(s)},'firmware_detected':None} for d,s in zip(selected,['SUPPORTED','NOT_EXPOSED','TIMEOUT'])]
    m=next(r for r in matrix(ds,obs) if r['feature']=='video_ch01')
    assert m['supported']==1 and m['not_exposed']==1 and m['inconclusive']==1 and m['not_sampled']==3 and m['classification']=='MIXED'
def test_duplicate_and_disabled(tmp_path):
    r={'ip':'192.0.2.1','device_type':'NVR','model':'X'}
    p=tmp_path/'devices.json';p.write_text(json.dumps([r,r,{**r,'ip':'192.0.2.2','snmp_enabled':False}]))
    ds,s=load_inventory(p)
    assert not ds and s['duplicate_endpoint']==2 and s['not_eligible']==1
