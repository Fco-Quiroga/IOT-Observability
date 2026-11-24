import copy,csv,hashlib,json
from collections import defaultdict
from pathlib import Path
SECRET='__SNMP_COMMUNITY_FROM_ENV__'
FEATURES={'interfaces','traffic','traffic32','memory','cpu_ucd','identity'}
def routes(path,key):
    if not path: return {}
    result={}
    with open(path,encoding='utf-8-sig',newline='') as f:
        for r in csv.DictReader(f):
            k=r[key].strip(); v=r['activegate_group'].strip()
            if not k or not v or (k in result and result[k]!=v): raise ValueError('Invalid route')
            result[k]=v
    return result
def build(s,group='SNMP',size=100,features=(),branch_routes=None,region_routes=None,timeout=2,retries=0,enabled=False,max_repetitions=5,max_oids=8,unconnected=True,namespace='full'):
    if not 1<=size<=100 or not set(features)<=FEATURES or {'traffic','traffic32'}<=set(features) or timeout<=0 or retries<0 or max_repetitions<1 or max_oids<1: raise ValueError('Invalid SNMP configuration')
    br={r['branch_id']:r for r in s['branches']}; groups=defaultdict(list); seen=set()
    for d in s['devices']:
        if not d['enabled'] or not d['snmp_enabled']: continue
        g=(branch_routes or {}).get(d['branch_id'],(region_routes or {}).get(br[d['branch_id']]['region'],group)); key=(g,d['ip'],d['snmp_port'])
        if key in seen: raise ValueError('Duplicate endpoint')
        seen.add(key); groups[g].append(d)
    out=[]
    for g,ds in sorted(groups.items()):
        for i in range(0,len(ds),size):
            chunk=sorted(ds,key=lambda d:d['ci_id'])[i:i+size]; scope='ag_group-'+g
            description=f'iot-devices | {namespace} | {scope} | batch-{i//size+1:03}'
            out.append({'scope':scope,'value':{'version':'0.2.0','description':description,'enabled':enabled,'featureSets':sorted(features),'snmp':{'devices':[{'ip':d['ip'],'port':d['snmp_port'],'authentication':{'type':'SNMPv2c','community':SECRET},'advanced':{'timeoutSecs':timeout,'retries':retries,'maxRepetitions':max_repetitions,'maxOidsPerQuery':max_oids,'enableUnconnectedUdp':unconnected}} for d in chunk]}}})
    return out
def endpoints(c): return {(c['scope'],d['ip'],d.get('port',161)) for d in c['value']['snmp']['devices']}
def signature(c):
    v=copy.deepcopy(c['value']); ds=v['snmp']['devices']
    for d in ds: d['authentication']={'type':d.get('authentication',{}).get('type')}
    v['snmp']['devices']=sorted(ds,key=lambda d:(d['ip'],d.get('port',161))); v['featureSets']=sorted(v.get('featureSets',[]))
    return {'scope':c['scope'],'value':v}
def plan(desired,existing):
    result=[]
    for c in desired:
        matches=[e for e in existing if e.get('scope')==c['scope'] and e.get('value',{}).get('description')==c['value']['description']]
        overlap=[e for e in existing if e not in matches and {(ip,p) for _,ip,p in endpoints(c)} & {(ip,p) for _,ip,p in endpoints(e)}]
        if len(matches)>1 or overlap: result.append(('BLOCK',c,None)); continue
        if not matches: result.append(('CREATE',c,None)); continue
        e=matches[0]; action='SKIP' if signature(c)==signature(e) else 'UPDATE'
        result.append((action,c,e['objectId']))
    return result
def inject(c,community):
    if not community: raise ValueError('Missing SNMP_COMMUNITY')
    c=copy.deepcopy(c)
    for d in c['value']['snmp']['devices']: d['authentication']['community']=community
    return c
