import os,time,requests
from urllib.parse import urlparse
class Client:
    def __init__(self,url,token,auth='api-token'):
        p=urlparse(url)
        if p.scheme!='https' or not p.hostname or p.username or p.password or p.query or p.fragment: raise ValueError('HTTPS tenant URL required')
        if not token: raise ValueError('Missing token')
        auth=auth.lower(); schemes={'api-token':'Api-Token','bearer':'Bearer'}
        if auth not in schemes: raise ValueError('Unsupported authentication')
        self.url=url.rstrip('/'); self.session=requests.Session(); self.session.headers['Authorization']=schemes[auth]+' '+token
    def request(self,method,path,**kwargs):
        for attempt in range(4):
            try: r=self.session.request(method,self.url+path,timeout=(10,90),allow_redirects=False,**kwargs)
            except requests.RequestException: raise RuntimeError('Transport error; reconcile remote state before retrying writes') from None
            if method=='GET' and (r.status_code==429 or r.status_code>=500) and attempt<3: time.sleep(min(30,2**attempt)); continue
            if not 200<=r.status_code<300 or r.status_code==207: raise RuntimeError(f'HTTP {r.status_code}; review tenant securely; reconcile before retry')
            return r
    def configurations(self,path):
        result=[]; params={}; cursors=set()
        while True:
            page=self.request('GET',path,params=params).json()
            if not isinstance(page,dict) or not isinstance(page.get('items'),list): raise RuntimeError('Unexpected configuration list response')
            result.extend(page['items']); cursor=page.get('nextPageKey') or page.get('next-page-key')
            if not cursor and isinstance(page.get('totalCount'),int) and len(result)!=page['totalCount']: raise RuntimeError('Incomplete configuration list; review remote state')
            if not cursor: return result
            if cursor in cursors: raise RuntimeError('Repeated pagination cursor')
            cursors.add(cursor); params={'page-key':cursor}

    def create_configuration(self,path,configuration):
        r=self.request('POST',path,json=configuration)
        response=r.json()
        if r.status_code!=201 or not isinstance(response,dict) or response.get('code')!=201 or not response.get('objectId'):
            raise RuntimeError('Create not confirmed; reconcile remote state')
        return response['objectId']
    def update_configuration(self,path,value,object_id):
        r=self.request('PUT',path,json={'value':value})
        response=r.json()
        if r.status_code!=200 or not isinstance(response,dict) or response.get('code')!=200 or response.get('objectId')!=object_id:
            raise RuntimeError('Update not confirmed; reconcile remote state')
