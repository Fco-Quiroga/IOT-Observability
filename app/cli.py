import argparse,os,json,time,hashlib,sys
from pathlib import Path
from urllib.parse import quote
from dotenv import load_dotenv
from .inventory import normalize,load,dump
from . import topology,lookup,activegate
from .dynatrace_client import Client
ROOT=Path(__file__).resolve().parents[1]
BASE='/platform/extensions/v2/extensions/custom:bank-iot-snmp/monitoring-configurations'
RESOURCE='/platform/storage/resource-store/v1/files/tabular/lookup:'
def common(p):
    p.add_argument('--out',type=Path,default=Path('out')); p.add_argument('--inventory',type=Path,default=Path('data')); p.add_argument('--registry',type=Path,default=Path('state/identities.json')); p.add_argument('--aliases',type=Path,default=ROOT/'config/inventory_aliases.yaml'); p.add_argument('--repair-coordinates',action='store_true')
    p.add_argument('--branch'); p.add_argument('--region'); p.add_argument('--device-type',choices=['IP_CAMERA','NVR']); p.add_argument('--selection',type=Path); p.add_argument('--limit',type=int); p.add_argument('--full',action='store_true'); p.add_argument('--allow-provisional',action='store_true'); p.add_argument('--security-context',default='',type=str.strip,help='Optional authorized Smartscape security context; omitted from events when empty')
def controls(p):
    m=p.add_mutually_exclusive_group(); m.add_argument('--dry-run',action='store_true'); m.add_argument('--apply',action='store_true'); m.add_argument('--preflight',action='store_true',help='Validate a proposed write without modifying Dynatrace')
    p.add_argument('--confirm-apply',action='store_true'); p.add_argument('--confirm-bulk',action='store_true'); p.add_argument('--check-access',action='store_true'); p.add_argument('--auth',choices=['api-token','bearer'],type=str.lower,default='bearer')
def parser():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest='command',required=True)
    for name in ('validate','configure','topology','export','upload'):
        q=sub.add_parser(name); common(q)
        if name in ('configure','topology','upload'): controls(q)
        if name=='configure':
            q.add_argument('--group',default='SNMP'); q.add_argument('--batch-size',type=int,default=100); q.add_argument('--features',nargs='*',default=[]); q.add_argument('--branch-routes'); q.add_argument('--region-routes'); q.add_argument('--timeout',type=int,default=2); q.add_argument('--retries',type=int,default=0); q.add_argument('--max-repetitions',type=int,default=5); q.add_argument('--max-oids',type=int,default=8); q.add_argument('--connected-udp',action='store_true'); q.add_argument('--enable',action='store_true'); q.add_argument('--confirm-enable',action='store_true'); q.add_argument('--update-existing',action='store_true'); q.add_argument('--max-configs',type=int,default=1000)
        if name=='topology': q.add_argument('--previous',type=Path); q.add_argument('--resume',action='store_true'); q.add_argument('--refresh',action='store_true'); q.add_argument('--delay',type=float,default=.5)
        if name=='upload': q.add_argument('--confirm-overwrite',action='store_true'); q.add_argument('--overwrite',action='store_true'); q.add_argument('--manifest',type=Path)
    return p
def snapshot(a):
    s,r,audit=normalize(a.inventory,a.registry,a.aliases,a.repair_coordinates)
    for b in s['branches']: b['security_context']=a.security_context or None
    dump(a.out/'inventory_report.json',r); dump(a.out/'audit.json',audit); dump(a.out/'normalized_inventory.json',s)
    print(json.dumps(r,ensure_ascii=False)); return s,r

def select(s,a,pilot_default=False):
    if a.limit is not None and a.limit<=0: raise ValueError('Positive limit required')
    filters=bool(a.branch or a.region or a.device_type or a.selection or a.limit is not None)
    if a.full and filters: raise ValueError('--full cannot be combined with selection')
    if not filters and (a.full or not pilot_default): return s,False
    br={b['branch_id']:b for b in s['branches']}; ids=None
    if a.selection:
        import csv
        content=a.selection.read_text(encoding='utf-8-sig').splitlines(); ids={x.strip() for line in content for x in next(csv.reader([line])) if x.strip() not in ('ci_id','ip','')}
    ds=[d for d in s['devices'] if (not a.branch or d['branch_id']==a.branch) and (not a.region or br[d['branch_id']]['region']==a.region) and (not a.device_type or d['device_type']==a.device_type) and (ids is None or d['ci_id'] in ids or d['ip'] in ids)]
    if a.limit is not None or not filters: ds=ds[:a.limit or 20]
    if not ds: raise ValueError('Empty selection')
    bs={d['branch_id'] for d in ds}; zs={d['zone_id'] for d in ds}
    return {'devices':ds,'branches':[b for b in s['branches'] if b['branch_id'] in bs],'zones':[z for z in s['zones'] if z['zone_id'] in zs]},True

def require_complete(report):
    # Full publication must not silently lose source entities after deduplication.
    if not isinstance(report,dict) or not isinstance(report.get('input'),dict) or not isinstance(report.get('active'),dict):
        raise ValueError('FULL blocked: missing inventory completeness report')
    lost={}
    for kind in ('branches','zones','devices'):
        raw,active=report['input'].get(kind),report['active'].get(kind)
        if not isinstance(raw,int) or not isinstance(active,int) or raw<0 or active<0:
            raise ValueError('FULL blocked: invalid inventory counts')
        if active<raw: lost[kind]={'input':raw,'active':active,'excluded':raw-active}
    if not report['active']['devices'] or not report['active']['branches']:
        raise ValueError('FULL blocked: empty inventory')
    if lost: raise ValueError('FULL blocked: incomplete inventory '+json.dumps(lost)+'; correct source and review audit.json')

def guard(a,n,pilot,provisional=False):
    if not a.confirm_apply: raise ValueError('--confirm-apply required')
    if not pilot and not a.full: raise ValueError('--full required for complete writes')
    if (n>20 or not pilot) and not a.confirm_bulk: raise ValueError('--confirm-bulk required')
    if provisional and not a.allow_provisional: raise ValueError('--allow-provisional required after identity audit')

def configure(a,s,pilot):
    if a.enable and not a.confirm_enable: raise ValueError('--confirm-enable required')
    configs=activegate.build(s,a.group,a.batch_size,a.features,activegate.routes(a.branch_routes,'branch_id'),activegate.routes(a.region_routes,'region'),a.timeout,a.retries,a.enable,a.max_repetitions,a.max_oids,not a.connected_udp,'pilot' if pilot else 'full')
    dump(a.out/'monitoring-configurations.json',configs)
    if not a.apply and not a.check_access and not a.preflight: return
    if a.auth!='bearer': raise ValueError('Platform API requires Bearer authentication')
    client=Client(os.getenv('DT_APPS_URL',''),os.getenv('DT_PLATFORM_TOKEN') or os.getenv('DT_API_TOKEN'),'bearer'); old=client.configurations(BASE)
    plan=activegate.plan(configs,old)
    desired_keys={(c['scope'],c['value']['description']) for c in configs}
    prefix='iot-devices | '+('pilot' if pilot else 'full')+' | '
    existing_summary=[{'id':e['objectId'],'scope':e['scope'],'description':e['value'].get('description'),'enabled':e['value'].get('enabled'),'endpoints':len(e['value']['snmp']['devices'])} for e in old]
    stale=[e for e in existing_summary if (e['description'] or '').startswith(prefix) and (e['scope'],e['description']) not in desired_keys]
    dump(a.out/'existing-configurations.json',existing_summary)
    dump(a.out/'configuration-plan.json',[{'action':k,'description':c['value']['description'],'id':i} for k,c,i in plan]+[{'action':'BLOCK_STALE','description':e['description'],'id':e['id']} for e in stale]); print('Existing configurations:',len(old))
    if not a.apply and not a.preflight: return
    guard(a,sum(len(c['value']['snmp']['devices']) for c in configs),pilot)
    if not configs: raise ValueError('No eligible SNMP endpoints')
    if len(configs)>a.max_configs or stale or any(k=='BLOCK' for k,c,i in plan): raise ValueError('Configuration limit, stale managed batch or overlap; review configuration-plan.json and existing-configurations.json; no automatic deletion')
    if any(k=='UPDATE' for k,c,i in plan) and not a.update_existing: raise ValueError('--update-existing required')
    if a.enable and any(k=='CREATE' for k,c,i in plan): raise ValueError('Create disabled first, then enable existing configurations')
    if any(k!='SKIP' for k,c,i in plan) and not os.getenv('SNMP_COMMUNITY'): raise ValueError('Missing SNMP_COMMUNITY')
    if a.preflight: print('Configuration preflight OK; no write'); return
    results=[]
    for k,c,i in plan:
        if k=='SKIP': continue
        c=activegate.inject(c,os.getenv('SNMP_COMMUNITY'))
        if k=='CREATE':
            i=client.create_configuration(BASE,c)
        else: client.update_configuration(BASE+'/'+quote(i,safe=''),c['value'],i)
        results.append({'action':k,'id':i}); dump(a.out/'configuration-applied.json',results)

def publish_topology(a,s,pilot):
    es=topology.build(s,a.security_context); dump(a.out/'topology.json',es)
    if a.previous:
        delta=topology.diff(load(a.previous),es); dump(a.out/'topology-diff.json',delta)
        if not a.refresh: es=[e for e in es if e in delta['added'] or e in delta['changed']]
    if not a.apply and not a.preflight:
        if a.check_access: print('No non-writing permission probe for Smartscape ingest; verify token scopes in IAM.')
        return
    guard(a,len(s['devices']),pilot,any(d['identity_source']!='CI_ID' for d in s['devices']))
    client=Client(os.getenv('DT_ENV_URL',''),os.getenv('DT_PLATFORM_TOKEN') or os.getenv('DT_TOPOLOGY_TOKEN'),a.auth)
    checkpoint=a.out/'topology-checkpoint.json'; scope=hashlib.sha256((client.url+a.security_context).encode()+topology.payload(es)).hexdigest()
    accepted=set()
    if a.resume and checkpoint.exists():
        old=load(checkpoint)
        if old['scope']!=scope: raise ValueError('Checkpoint does not match plan/tenant')
        accepted=set(old['accepted'])
    batches=list(topology.batches(es))
    if a.preflight: print('Topology preflight OK; no ingest; IAM write scope not remotely verified'); return
    for batch in batches:
        body=topology.payload(batch); h=topology.digest(body)
        if h in accepted: continue
        r=client.request('POST','/platform/ingest/v1/smartscape.events',data=body,headers={'Content-Type':'application/json'})
        accepted.add(h); dump(checkpoint,{'scope':scope,'accepted':sorted(accepted),'last_http':r.status_code}); time.sleep(max(.1,a.delay))

def upload(a):
    mp=a.manifest or a.out/'lookup_manifest.json'; manifest=load(mp); files=manifest['files']; pilot=manifest['pilot']
    expected={'iot_devices.jsonl':'ci_id','iot_branches.jsonl':'branch_id','iot_zones.jsonl':'zone_id'}
    if set(f['file'] for f in files)!=set(expected) or len(files)!=3: raise ValueError('Incomplete manifest')
    payloads=[]
    for f in files:
        name=f['file']; path=mp.parent/name; data=path.read_bytes(); rows=[json.loads(l) for l in data.splitlines() if l]; key=expected[name]
        if not rows or len(rows)!=f['count'] or len(data)!=f['size'] or hashlib.sha256(data).hexdigest()!=f['sha256'] or len({r[key] for r in rows})!=len(rows): raise ValueError('Lookup empty or integrity check failed')
        if f['lookupField']!=key or f['filePath']!='/lookups/iot'+('/piloto' if pilot else '')+'/'+path.stem: raise ValueError('Unsafe destination')
        if not pilot and manifest['report']['active'][{'iot_devices.jsonl':'devices','iot_branches.jsonl':'branches','iot_zones.jsonl':'zones'}[name]]!=len(rows): raise ValueError('Partial production snapshot')
        payloads.append((f,data))
    if not a.apply and not a.check_access and not a.preflight: print('Manifest verified'); return
    if a.apply or a.preflight:
        if not pilot: require_complete(manifest['report'])
        guard(a,next(f['count'] for f in files if f['file']=='iot_devices.jsonl'),pilot)
        if a.overwrite and not a.confirm_overwrite: raise ValueError('--confirm-overwrite required')
    c=Client(os.getenv('DT_APPS_URL',''),os.getenv('DT_PLATFORM_TOKEN') or os.getenv('DT_LOOKUP_TOKEN'),'bearer')
    # Parse all first; no write until all previews pass.
    def form(f,data,write):
        params={'parsePattern':'JSON:json','lookupField':f['lookupField']}
        if write: params.update(filePath=f['filePath'],overwrite=a.overwrite)
        return {'request':(None,json.dumps(params),'application/json'),'content':(f['file'],data,'application/octet-stream')}
    for f,data in payloads:
        r=c.request('POST',RESOURCE+'test-pattern',files=form(f,data,False)); preview=r.json()
        if preview.get('numberOfRecords')!=f['count']: raise RuntimeError('Remote parse count mismatch; no upload performed')
        print('Parse preview HTTP',r.status_code,f['file'])
    if a.apply:
        for f,data in payloads:
            r=c.request('POST',RESOURCE+'upload',files=form(f,data,True)); result=r.json()
            if result.get('records')!=f['count'] or result.get('discardedDuplicates')!=0: raise RuntimeError('Remote upload count mismatch; review uploaded file before continuing')
            print('Upload HTTP',r.status_code,f['file'])

def main(argv=None):
    load_dotenv(); a=parser().parse_args(argv); a.out.mkdir(parents=True,exist_ok=True)
    try:
        if a.command=='upload': upload(a); return
        s,r=snapshot(a)
        if a.command=='validate': return
        s,pilot=select(s,a,pilot_default=a.command in ('configure','topology'))
        if (getattr(a,'apply',False) or getattr(a,'preflight',False)) and not pilot: require_complete(r)
        if a.command=='configure': configure(a,s,pilot)
        elif a.command=='topology': publish_topology(a,s,pilot)
        elif a.command=='export': lookup.export(s,a.out,pilot=pilot,report=r)
    except (ValueError,RuntimeError,KeyError,OSError) as e: print('ERROR:',str(e),file=sys.stderr); raise SystemExit(1)
if __name__=='__main__': main()
