"""Bounded, read-only SNMP capability discovery for authorized inventory endpoints."""
import argparse, asyncio, csv, hashlib, ipaddress, json, os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path

ROOT='1.3.6.1.4.1.36849.1.9.'
SCALARS={
 'uptime':'1.3.6.1.2.1.1.3.0',
 'sysname':'1.3.6.1.2.1.1.5.0',
 'sysobjectid':'1.3.6.1.2.1.1.2.0',
 'cpu_idle':'1.3.6.1.4.1.2021.11.11.0',
 'memory_total':'1.3.6.1.4.1.2021.4.5.0',
 'memory_available':'1.3.6.1.4.1.2021.4.6.0',
 'model_reported':ROOT+'1.0',
 'firmware':ROOT+'2.1.1.0',
 'channel_count':ROOT+'2.2.3.0',
 'video_ch01':ROOT+'3.2.1.0',
 'recording':ROOT+'3.3.1.0',
 'fan':ROOT+'3.3.2.0',
 'battery':ROOT+'3.3.3.0',
}
COLUMNS={'interface_status':'1.3.6.1.2.1.2.2.1.8',
         'traffic_rx64':'1.3.6.1.2.1.31.1.1.1.6',
         'traffic_tx64':'1.3.6.1.2.1.31.1.1.1.10'}
EXPECTED={'video':{'on','vloss','disable'},'recording':{'on','off','fail'},
          'fan':{'ok','fail'},'battery':{'ok','fail'}}
def result(status,value=None):
    return {'status':status,'value':value}
def classify(name,value):
    from pysnmp.proto.rfc1905 import NoSuchObject, NoSuchInstance, EndOfMibView
    if isinstance(value,(NoSuchObject,NoSuchInstance,EndOfMibView)):
        return result('NOT_EXPOSED')
    s=value.prettyPrint().strip()
    if s.casefold() in ('notsupported','not supported','unsupported','not applicable','n/a'):
        return result('NOT_SUPPORTED',s)
    if not s: return result('UNKNOWN_VALUE')
    key='video' if name.startswith('video_ch') else name
    if key in EXPECTED and s.casefold() not in EXPECTED[key]:
        return result('UNKNOWN_VALUE',s)
    return result('SUPPORTED',s)
def load_inventory(path):
    p=Path(path)
    if p.suffix.lower()=='.jsonl':
        records=[json.loads(line) for line in p.read_text(encoding='utf-8-sig').splitlines() if line.strip()]
    else:
        records=json.loads(p.read_text(encoding='utf-8-sig'))
        if isinstance(records,dict):
            records=next((records[k] for k in ('devices','cameras','data') if isinstance(records.get(k),list)),None)
    if not isinstance(records,list) or any(not isinstance(r,dict) for r in records):
        raise ValueError('Expected normalized devices JSON/JSONL')
    valid=[]; skipped=Counter()
    for r in records:
        typ=str(r.get('device_type','')).strip().upper()
        model=str(r.get('model') or '').strip().upper()
        if typ not in ('IP_CAMERA','NVR') or not model:
            skipped['missing_type_or_model']+=1; continue
        if r.get('enabled',True) is not True or r.get('snmp_enabled',True) is not True:
            skipped['not_eligible']+=1; continue
        try:
            ip=ipaddress.ip_address(str(r.get('ip','')).strip())
            port=int(r.get('snmp_port',r.get('port',161)))
            if ip.is_unspecified or ip.is_multicast or ip.is_loopback or not 1<=port<=65535: raise ValueError()
        except (ValueError,TypeError,OverflowError):
            skipped['invalid_endpoint']+=1; continue
        valid.append({'ci_id':str(r.get('ci_id') or ''),'ip':str(ip),'port':port,'device_type':typ,
            'manufacturer':str(r.get('manufacturer') or r.get('manufactorer') or 'UNKNOWN').strip().upper(),
            'model':model,'branch_id':str(r.get('branch_id') or ''),
            'firmware_inventory':str(r.get('firmware') or r.get('firmware_version') or '').strip()})
    counts=Counter((d['ip'],d['port']) for d in valid)
    skipped['duplicate_endpoint']+=sum(n for n in counts.values() if n>1)
    return [d for d in valid if counts[(d['ip'],d['port'])]==1],dict(skipped)
def group(d):
    return (d['device_type'],d['manufacturer'],d['model'],d['firmware_inventory'])
def sample(devices,n,seed):
    groups=defaultdict(list)
    for d in devices: groups[group(d)].append(d)
    selected=[]
    for key,ds in sorted(groups.items()):
        ranked=sorted(ds,key=lambda d:hashlib.sha256(f"{seed}|{d['ip']}|{d['port']}".encode()).hexdigest())
        first=[]; other=[]; seen=set()
        for d in ranked:
            if d['branch_id'] in seen: other.append(d)
            else: first.append(d); seen.add(d['branch_id'])
        selected.extend((first+other)[:n])
    return selected

async def discover(devices,community,concurrency,timeout,retries,channels):
    from pysnmp.hlapi.v3arch.asyncio import (SnmpEngine, CommunityData, ContextData,
        UdpTransportTarget, Udp6TransportTarget, ObjectType, ObjectIdentity, get_cmd, next_cmd)
    engine=SnmpEngine(); auth=CommunityData(community,mpModel=1)
    gate=asyncio.Semaphore(concurrency)
    async def one(d):
        async with gate:
            target_type=Udp6TransportTarget if ':' in d['ip'] else UdpTransportTarget
            checks={}
            try:
                target=await target_type.create((d['ip'],d['port']),timeout=timeout,retries=retries)
                async def ask(items,next_=False):
                    fn=next_cmd if next_ else get_cmd
                    try:
                        err,status,index,bindings=await fn(engine,auth,target,ContextData(),
                            *[ObjectType(ObjectIdentity(oid)) for _,oid in items],lookupMib=False)
                    except Exception:
                        return {name:result('ERROR') for name,_ in items}
                    if err:
                        state='TIMEOUT' if 'timed out' in str(err).lower() or 'timeout' in str(err).lower() else 'ERROR'
                        return {name:result(state) for name,_ in items}
                    if status or len(bindings)!=len(items):
                        return {name:result('ERROR') for name,_ in items}
                    out={}
                    for (name,oid),(returned,value) in zip(items,bindings):
                        actual=returned.prettyPrint().lstrip('.')
                        if next_ and not actual.startswith(oid+'.'):
                            out[name]=result('NOT_EXPOSED')
                        elif not next_ and actual!=oid:
                            out[name]=result('ERROR')
                        else:
                            out[name]=classify(name,value)
                        out[name]['returned_oid']=actual
                    return out
                checks.update(await ask([('uptime',SCALARS['uptime'])]))
                if checks['uptime']['status']!='SUPPORTED':
                    for name in (*SCALARS,*COLUMNS):
                        checks.setdefault(name,result('NOT_TESTED'))
                else:
                    items=list(SCALARS.items())[1:]
                    for pos in range(0,len(items),4):
                        checks.update(await ask(items[pos:pos+4]))
                    for name,oid in COLUMNS.items():
                        checks.update(await ask([(name,oid)],True))
                    if d['device_type']=='NVR' and channels>1:
                        try: maximum=min(channels,int(checks['channel_count']['value']))
                        except (ValueError,TypeError): maximum=channels
                        items=[(f'video_ch{i:02}',ROOT+f'3.2.{i}.0') for i in range(2,maximum+1)]
                        for pos in range(0,len(items),4):
                            checks.update(await ask(items[pos:pos+4]))
            except Exception:
                for name in (*SCALARS,*COLUMNS):
                    checks.setdefault(name,result('ERROR'))
            row={**d,'firmware_detected':checks.get('firmware',{}).get('value'),
                 'checked_at':datetime.now(timezone.utc).isoformat(),'checks':checks}
            print('Completed',d['device_type'],d['model'],checks.get('uptime',{}).get('status'),flush=True)
            return row
    try: return await asyncio.gather(*(one(d) for d in devices))
    finally: engine.close_dispatcher()

def matrix(devices,observations):
    population=Counter(group(d) for d in devices)
    by=defaultdict(list)
    for d in observations: by[group(d)].append(d)
    output=[]
    for key,total in sorted(population.items()):
        tested=by[key]
        features=sorted(set(SCALARS)|set(COLUMNS)|{k for d in tested for k in d['checks']})
        for feature in features:
            counts=Counter(d['checks'].get(feature,{}).get('status','NOT_TESTED') for d in tested)
            good=counts['SUPPORTED']; absent=counts['NOT_EXPOSED']+counts['NOT_SUPPORTED']
            unknown=len(tested)-good-absent
            label=('MIXED' if good and absent else 'SUPPORTED_IN_SAMPLE' if good and not unknown else
                   'NOT_SUPPORTED_OR_EXPOSED_IN_SAMPLE' if absent and not unknown else 'INCONCLUSIVE')
            output.append(dict(zip(('device_type','manufacturer','model','firmware_inventory'),key),
                population=total,sampled=len(tested),feature=feature,supported=good,
                not_exposed=counts['NOT_EXPOSED'],not_supported=counts['NOT_SUPPORTED'],
                inconclusive=unknown,not_sampled=total-len(tested),classification=label,
                supported_pct_sample=round(100*good/len(tested),2) if tested else None,
                firmware_detected='; '.join(sorted({str(d['firmware_detected']) for d in tested if d.get('firmware_detected')}))))
    return output
def csv_write(path,rows):
    if not rows: return
    with path.open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--per-model',type=int,default=3)
    p.add_argument('--seed',default='pilot-1')
    p.add_argument('--concurrency',type=int,default=4)
    p.add_argument('--timeout',type=float,default=2)
    p.add_argument('--retries',type=int,default=0)
    p.add_argument('--nvr-channels',type=int,default=4)
    p.add_argument('--max-targets',type=int,default=120)
    p.add_argument('--apply',action='store_true',help='Perform read-only SNMP requests')
    p.add_argument('--confirm-authorized',action='store_true')
    a=p.parse_args()
    if not (1<=a.per_model<=20 and 1<=a.concurrency<=12 and .5<=a.timeout<=10 and 0<=a.retries<=1 and 1<=a.nvr_channels<=64 and 1<=a.max_targets<=500):
        p.error('Unsafe limits')
    devices,skipped=load_inventory(a.inventory)
    selected=sample(devices,a.per_model,a.seed)
    if not selected or len(selected)>a.max_targets: p.error('Empty sample or max-targets exceeded')
    a.out.mkdir(parents=True,exist_ok=True)
    plan=[dict(zip(('device_type','manufacturer','model','firmware_inventory'),key),
        population=n,selected=sum(group(d)==key for d in selected)) for key,n in sorted(Counter(map(group,devices)).items())]
    csv_write(a.out/'sample_plan.csv',plan)
    print(json.dumps({'eligible':len(devices),'skipped':skipped,'sample':len(selected),'groups':len(plan)},ensure_ascii=False))
    if not a.apply: return
    if not a.confirm_authorized: p.error('Authorized network and endpoints must be confirmed')
    community=os.getenv('SNMP_COMMUNITY') or getpass('SNMP read-only community: ')
    if not community: p.error('Missing community')
    observations=asyncio.run(discover(selected,community,a.concurrency,a.timeout,a.retries,a.nvr_channels))
    (a.out/'device_results.jsonl').write_text(''.join(json.dumps(d,ensure_ascii=False)+'\n' for d in observations),encoding='utf-8')
    csv_write(a.out/'capability_matrix.csv',matrix(devices,observations))
    details=[]
    for d in observations:
        for feature,check in d['checks'].items():
            details.append({**{k:v for k,v in d.items() if k!='checks'},'feature':feature,
                            'status':check['status'],'value':check.get('value'),'returned_oid':check.get('returned_oid')})
    csv_write(a.out/'oid_results.csv',details)
    summary=[]
    for typ in ('IP_CAMERA','NVR'):
        pop=sum(d['device_type']==typ for d in devices); obs=[d for d in observations if d['device_type']==typ]
        for name in ('video_ch01','recording','cpu_idle','memory_total','interface_status'):
            cnt=Counter(d['checks'].get(name,{}).get('status','NOT_TESTED') for d in obs)
            good=cnt['SUPPORTED']; absent=cnt['NOT_EXPOSED']+cnt['NOT_SUPPORTED']
            summary.append({'device_type':typ,'feature':name,'eligible_population':pop,'sampled':len(obs),
                'supported':good,'not_exposed_or_supported':absent,'inconclusive':len(obs)-good-absent,
                'not_sampled':pop-len(obs),'supported_pct_sample':round(100*good/len(obs),2) if obs else None})
    csv_write(a.out/'coverage.csv',summary)
    print('Reports complete. Sample percentages are not fleet-wide estimates.')
if __name__=='__main__': main()
