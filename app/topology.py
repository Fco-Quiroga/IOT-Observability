import json,hashlib
TYPE={'IP_CAMERA':'CUSTOM_BANK_CAMERA','NVR':'CUSTOM_BANK_NVR'}
def ref(t,k,v): return {'type':t,'id_components':[{k:v}]}
def event(t,k,v,n,security,parent=None):
    e={'event.version':1,**ref(t,k,v),'name':n,'custom.bank.'+k:v,'dt.security_context':security}
    if parent: e['static_edges']={'belongs_to':[parent]}
    return e
def identity(e): return (e['type'],json.dumps(e['id_components'],sort_keys=True))
def build(s,security='security-iot'):
    out=[]
    for b in s['branches']: out.append(event('CUSTOM_BANK_BRANCH','branch_id',b['branch_id'],b['structural_name'],security))
    for z in s['zones']: out.append(event('CUSTOM_BANK_ZONE','zone_id',z['zone_id'],z['structural_name'],security,ref('CUSTOM_BANK_BRANCH','branch_id',z['branch_id'])))
    for d in s['devices']:
        p=ref('CUSTOM_BANK_ZONE','zone_id',d['zone_id']) if d['zone_id'] else ref('CUSTOM_BANK_BRANCH','branch_id',d['branch_id'])
        out.append(event(TYPE[d['device_type']],'ci_id',d['ci_id'],d['structural_name'],security,p))
    ids={identity(e) for e in out}
    if len(ids)!=len(out): raise ValueError('Duplicate topology identity')
    if any(identity(p) not in ids for e in out for p in e.get('static_edges',{}).get('belongs_to',[])): raise ValueError('Orphan edge')
    return out
def payload(es): return json.dumps(es,ensure_ascii=False,separators=(',',':')).encode()
def batches(events,max_events=80,max_bytes=160000):
    if not 1<=max_events<=80 or not 1<=max_bytes<=160000: raise ValueError('Batch bounds')
    batch=[]
    for e in events:
        if len(payload([e]))>max_bytes: raise ValueError('Oversize event')
        if batch and (len(batch)>=max_events or len(payload(batch+[e]))>max_bytes or batch[0]['type']!=e['type']): yield batch; batch=[]
        batch.append(e)
    if batch: yield batch
def diff(old,new):
    a={identity(e):e for e in old}; b={identity(e):e for e in new}
    return {'added':[b[k] for k in sorted(b.keys()-a.keys())],'removed':[a[k] for k in sorted(a.keys()-b.keys())],'changed':[b[k] for k in sorted(a.keys()&b.keys()) if a[k]!=b[k]]}
def digest(data): return hashlib.sha256(data).hexdigest()
