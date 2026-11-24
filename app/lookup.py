import csv, json, hashlib
from datetime import datetime,timezone
from pathlib import Path
from .inventory import dump
from .topology import TYPE

def export(s,out,root='/lookups/iot',pilot=False,report=None):
    out=Path(out); out.mkdir(parents=True,exist_ok=True)
    b={r['branch_id']:r for r in s['branches']}; z={r['zone_id']:r for r in s['zones']}; ds=[]
    for d in s['devices']:
        branch=b[d['branch_id']]; zone=z.get(d['zone_id'],{})
        row={k:v for k,v in d.items() if k!='structural_name'}
        row.update({k:branch.get(k) for k in ('office_type','address','city','commune','region','country','latitude','longitude','security_context')})
        row.update(branch_name=branch['name'],zone_name=zone.get('name'),zone_type=zone.get('type'),port=d['snmp_port'],smartscape_type=TYPE[d['device_type']])
        ds.append(row)
    manifest={'pilot':pilot,'generated_at':datetime.now(timezone.utc).isoformat(),'report':report or {},'files':[]}
    for name,key,records in [('iot_devices','ci_id',ds),('iot_branches','branch_id',s['branches']),('iot_zones','zone_id',s['zones'])]:
        records=sorted(records,key=lambda r:r[key]); ids=[r[key] for r in records]
        if len(ids)!=len(set(ids)): raise ValueError('Duplicate lookup keys')
        records=[{k:v for k,v in r.items() if k!='structural_name'} for r in records]
        data=''.join(json.dumps(r,ensure_ascii=False,sort_keys=True)+'\n' for r in records).encode(); path=out/(name+'.jsonl'); path.write_bytes(data)
        with (out/(name+'.csv')).open('w',encoding='utf-8-sig',newline='') as f:
            fields=sorted({k for r in records for k in r}); w=csv.DictWriter(f,fieldnames=[key]+[k for k in fields if k!=key]); w.writeheader(); w.writerows(records)
        manifest['files'].append({'file':path.name,'filePath':root+('/piloto' if pilot else '')+'/'+name,'lookupField':key,'count':len(records),'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'parsePattern':'JSON:json'})
    dump(out/'lookup_manifest.json',manifest); return manifest
