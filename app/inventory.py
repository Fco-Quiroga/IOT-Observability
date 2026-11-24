"""Normalize snapshots; no network access. Raw inventory stays outside Git."""
import json, re, unicodedata, ipaddress, hashlib, math
from pathlib import Path
from collections import Counter, defaultdict
import yaml

CRIT={None,'LOW','MEDIUM','HIGH','CRITICAL'}
def dump(path,data):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix(path.suffix+'.tmp'); tmp.write_text(json.dumps(data,ensure_ascii=False,indent=2,sort_keys=True)+'\n',encoding='utf-8'); tmp.replace(path)
def load(path): return json.loads(Path(path).read_text(encoding='utf-8-sig'))
def text(v): return ' '.join(unicodedata.normalize('NFC',str(v)).split()) if v is not None else ''
def norm(v): return ''.join(c for c in unicodedata.normalize('NFKD',text(v).casefold()) if not unicodedata.combining(c))
def rows(path,keys):
    obj=load(path)
    if isinstance(obj,dict):
        matches=[obj[k] for k in keys if isinstance(obj.get(k),list)]
        if len(matches)!=1: raise ValueError(f'Expected exactly one list: {path.name}')
        obj=matches[0]
    if not isinstance(obj,list) or any(not isinstance(r,dict) for r in obj): raise ValueError(f'Invalid records: {path.name}')
    return obj
def mac(v):
    s=re.sub(r'[:.\-]','',text(v)).upper()
    if not re.fullmatch('[0-9A-F]{12}',s) or s in ('000000000000','FFFFFFFFFFFF') or int(s[:2],16)&1: return None
    return ':'.join(s[i:i+2] for i in range(0,12,2))
def ip(v):
    try: return str(ipaddress.ip_address(text(v)))
    except ValueError: return None
def port(v):
    try:
        if isinstance(v,bool) or int(v)!=float(v) or not 1<=int(v)<=65535: return None
        return int(v)
    except (ValueError,TypeError,OverflowError): return None
def coord(v,axis,repair):
    try:
        if isinstance(v,bool): return None
        n=float(v)
        if not math.isfinite(n): return None
    except (ValueError,TypeError): return None
    limit=90 if axis=='lat' else 180
    if abs(n)<=limit and n!=0: return n
    if not repair or n!=int(n): return None
    low,high=(-56,-17) if axis=='lat' else (-110,-66)
    candidates=[n/10**p for p in range(1,12) if low<=n/10**p<=high]
    return candidates[0] if len(candidates)==1 else None
def endpoint(address,p): return (f'[{address}]:{p}' if ':' in address else f'{address}:{p}') if address and p else None
def token(s): return hashlib.sha256(s.encode()).hexdigest()[:24].upper()
def zone_key(b,z): return f'{b}:{z}'
def clean_extra(r):
    # Explicit allowlist: do not copy arbitrary fields which could carry secrets.
    return {k:r[k] for k in ('uuid','office_type','security_context','topology_status','serial_number','asset_tag','network_context') if k in r}
def normalize(directory, registry_path, aliases_path, repair=False):
    directory=Path(directory); aliases=yaml.safe_load(Path(aliases_path).read_text()); registry_path=Path(registry_path)
    registry=load(registry_path) if registry_path.exists() else {'keys':{},'names':{},'observations':{}}
    audit=[]
    def scrub(v):
        if isinstance(v,dict): return {k:scrub(x) for k,x in v.items() if not any(t in k.casefold() for t in ('password','community','secret','token','credential','authorization','private_key','api_key'))}
        if isinstance(v,list): return [scrub(x) for x in v]
        return v
    def issue(kind,entity,record,**details): audit.append(scrub(dict(kind=kind,entity=entity,record=record,**details)))
    bp=directory/'branches.json'; bp=bp if bp.exists() else directory/'brunches.json'
    bs=rows(bp,['branches','brunches','data']); zs=rows(directory/'zones.json',['zones','data']); ds=rows(directory/'cameras.json',['cameras','devices','data'])
    if (directory/'nvrs.json').exists(): ds+=rows(directory/'nvrs.json',['nvrs','devices','data'])
    # Exact duplicates only; preserve collisions between distinct objects.
    def dedup(seq,entity):
        out=[]; seen=set()
        for r in seq:
            key=json.dumps(r,sort_keys=True,ensure_ascii=False)
            if key in seen: issue('exact_duplicate',entity,r); continue
            seen.add(key); out.append(r)
        return out
    ds=dedup(ds,'device'); bs=dedup(bs,'branch'); zs=dedup(zs,'zone')
    branch_counts=Counter(text(r.get('branch_id',r.get('ID Sucursal'))) for r in bs)
    branches={}; zone_map={}; devices=[]
    name_alias={norm(k):norm(v) for k,v in aliases.get('branch_names',{}).items()}
    def bname(v):
        n=norm(v); return name_alias.get(n,n).removeprefix('sucursal ')
    def critical(r,entity):
        val=r.get('criticality'); val=text(val).upper() if val is not None and text(val) else None
        if val not in CRIT: issue('invalid_criticality',entity,r); return None
        return val
    for r in bs:
        bid=text(r.get('branch_id',r.get('ID Sucursal'))); latraw=r.get('latitude',r.get('location.lat')); lonraw=r.get('longitude',r.get('ubicación.location.lon'))
        lat,lon=coord(latraw,'lat',repair),coord(lonraw,'lon',repair)
        if not bid or branch_counts[bid]>1 or lat is None or lon is None:
            issue('excluded_branch', 'branch',r,reason='missing/duplicate ID or invalid coordinates'); continue
        if lat!=latraw or lon!=lonraw: issue('coordinate_normalization','branch',r,latitude=lat,longitude=lon)
        name=text(r.get('name')) or bid
        branches[bid]={**clean_extra(r),'branch_id':bid,'name':name,'office_type':r.get('office_type'),'address':r.get('address',r.get('location_street')),'city':r.get('city',r.get('Ciudad')),'commune':r.get('commune',r.get('Comuna')),'region':r.get('region',r.get('Región')),'country':r.get('country'),'latitude':lat,'longitude':lon,'criticality':critical(r,'branch'),'topology_status':'ACTIVE'}
        for zz in r.get('zones',[]):
            if not isinstance(zz,dict): raise ValueError('Invalid nested zone')
            zs.append({**zz,'branch_id':bid})
    byname=defaultdict(list)
    for bid,b in branches.items(): byname[bname(b['name'])].append(bid)
    for k,ids in byname.items():
        if len(ids)>1: issue('ambiguous_branch_name','branch',{'branch_ids':ids})
    def branch_ref(r):
        bid=text(r.get('branch_id')); name=r.get('branch_name')
        if bid: return bid if bid in branches else None
        ids=byname.get(bname(name),[]); return ids[0] if len(ids)==1 else None
    conflicts=set()
    for r in zs:
        b=branch_ref(r); original=text(r.get('zone_id')); key=zone_key(b,original) if b and original else None
        if not key: issue('excluded_zone','zone',r); continue
        z={**clean_extra(r),'zone_id':key,'source_zone_id':original,'branch_id':b,'name':text(r.get('name',r.get('zone_name'))) or original,'type':r.get('type'),'criticality':critical(r,'zone'),'topology_status':'ACTIVE'}
        if key in zone_map:
            old=zone_map[key]; incompatible=any(old.get(k) is not None and z.get(k) is not None and (norm(old[k])!=norm(z[k]) if k=='name' else old[k]!=z[k]) for k in ('name','type','criticality'))
            if incompatible: conflicts.add(key); issue('zone_conflict','zone',r,previous=old)
            else: zone_map[key]={**z,**{k:v for k,v in old.items() if v is not None}}
        else: zone_map[key]=z
    for key in conflicts: zone_map.pop(key,None)
    ci_counts=Counter(text(r.get('ci_id')) for r in ds); mac_counts=Counter(mac(r.get('mac')) for r in ds)
    endpoint_counts=Counter(endpoint(ip(r.get('ip')),port(r.get('snmp_port',161))) for r in ds)
    # Match persisted source CI + unique MAC/IP evidence. Never auto-remap ambiguous changes.
    for r in ds:
        b=branch_ref(r); oldci=text(r.get('ci_id')); m=mac(r.get('mac')); a=ip(r.get('ip')); p=port(r.get('snmp_port',161)); model=text(r.get('model')); manufacturer=text(r.get('manufacturer',r.get('manufactorer')))
        if not b: issue('excluded_device_branch','device',r); continue
        zid=text(r.get('zone_id')); z=zone_key(b,zid) if zid else None
        if z and z not in zone_map: issue('excluded_device_zone','device',r); continue
        if r.get('branch_name') and bname(r['branch_name'])!=bname(branches[b]['name']): issue('branch_name_mismatch','device',r,canonical_branch=b)
        typ=text(r.get('device_type')).upper()
        if norm(manufacturer)=='hanwha' and model.upper() in aliases.get('nvr_models',[]):
            if typ!='NVR': issue('nvr_reclassification','device',r)
            typ='NVR'
        if typ not in ('IP_CAMERA','NVR'): issue('excluded_device_type','device',r); continue
        if not a or not p: issue('invalid_snmp_endpoint','device',r)
        if not m or mac_counts[m]>1: issue('invalid_or_duplicate_mac','device',r)
        official=bool(oldci and ci_counts[oldci]==1)
        context=text(r.get('network_context')) or b
        keys=[]
        if official: keys.append('ci:'+oldci)
        if m and mac_counts[m]==1: keys.append('mac:'+m)
        if a and p and endpoint_counts[endpoint(a,p)]==1: keys.append('endpoint:'+context+':'+endpoint(a,p))
        known={registry['keys'][k] for k in keys if k in registry['keys']}
        if len(known)>1: issue('identity_conflict','device',r); continue
        if known:
            ci=next(iter(known)); source=registry['observations'][ci]['identity_source']
            if official and ci!=oldci: issue('cmdb_reconciliation_pending','device',r,existing_ci=ci)
            prev=registry['observations'][ci]
            if prev.get('mac') and m and prev['mac']!=m: issue('physical_identity_change','device',r,ci_id=ci)
            if source!='CI_ID' and not any(k.startswith('mac:') and registry['keys'].get(k)==ci for k in keys) and prev.get('mac') and m and prev['mac']!=m:
                issue('identity_review_required','device',r); continue
        elif official: ci=oldci; source='CI_ID'
        elif m and mac_counts[m]==1: ci='TEMP-MAC-'+token(m); source='PROVISIONAL_MAC'
        elif a and p and endpoint_counts[endpoint(a,p)]==1: ci='TEMP-ENDPOINT-'+token(context+':'+endpoint(a,p)); source='PROVISIONAL_ENDPOINT'
        else: issue('unresolved_identity','device',r); continue
        if not official: issue('provisional_identity','device',r,ci_id=ci,source=source)
        for k in keys: registry['keys'][k]=ci
        registry['observations'][ci]={'identity_source':source,'mac':m,'ip':a,'source_ci_id':oldci or None}
        registry['names'].setdefault(ci,('Camera ' if typ=='IP_CAMERA' else 'NVR ')+ci)
        enabled=r.get('enabled',True) is True
        d={**clean_extra(r),'ci_id':ci,'source_ci_id':oldci or None,'name':text(r.get('name')) or ci,'structural_name':registry['names'][ci],'device_type':typ,'manufacturer':manufacturer,'model':model,'ip':a,'mac':m,'snmp_port':p,'snmp_endpoint':endpoint(a,p),'enabled':enabled,'snmp_enabled':bool(enabled and r.get('snmp_enabled',True) is True and a and p),'branch_id':b,'zone_id':z,'criticality':critical(r,'device'),'interface_name':r.get('interface_name'),'nvr_ci_id':r.get('nvr_ci_id'),'identity_source':source,'topology_status':'PROVISIONAL' if source!='CI_ID' else 'ACTIVE','network_context':context}
        devices.append(d)
    counts=Counter(d['ci_id'] for d in devices); epcounts=Counter(d['snmp_endpoint'] for d in devices if d['snmp_endpoint'])
    result=[]
    for d in devices:
        if counts[d['ci_id']]>1: issue('resolved_identity_collision','device',d); continue
        d['endpoint_ambiguous']=bool(d['snmp_endpoint'] and epcounts[d['snmp_endpoint']]>1)
        if d['endpoint_ambiguous']: d['snmp_enabled']=False; issue('ambiguous_endpoint','device',d)
        result.append(d)
    valid_nvr={d['ci_id'] for d in result if d['device_type']=='NVR'}
    for d in result:
        if d['nvr_ci_id'] and d['nvr_ci_id'] not in valid_nvr: issue('unresolved_nvr_relation','device',d)
    for b in branches.values(): b['structural_name']=registry['names'].setdefault('branch:'+b['branch_id'],b['name'])
    for z in zone_map.values(): z['structural_name']=registry['names'].setdefault('zone:'+z['zone_id'],z['name'])
    snapshot={'branches':sorted(branches.values(),key=lambda r:r['branch_id']),'zones':sorted(zone_map.values(),key=lambda r:r['zone_id']),'devices':sorted(result,key=lambda r:r['ci_id'])}
    report={'input':{'devices':len(ds),'branches':len(bs),'zones':len(zs)},'active':{k:len(v) for k,v in snapshot.items()},'device_types':dict(Counter(d['device_type'] for d in result)),'snmp_enabled':sum(d['snmp_enabled'] for d in result),'provisional':sum(d['identity_source']!='CI_ID' for d in result),'audit_counts':dict(Counter(a['kind'] for a in audit)),'coordinate_repair':repair}
    dump(registry_path,registry)
    return snapshot,report,audit
