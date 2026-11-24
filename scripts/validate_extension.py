import argparse,json
from pathlib import Path
import yaml,jsonschema
from referencing import Registry,Resource
p=argparse.ArgumentParser(); p.add_argument('--schema-dir',type=Path,required=True); p.add_argument('--extension',type=Path,default=Path('extension.yaml')); a=p.parse_args()
files=list(a.schema_dir.rglob('*.json')); registry=Registry()
for f in files:
    obj=json.loads(f.read_text()); resource=Resource.from_contents(obj,default_specification=__import__('referencing.jsonschema',fromlist=['DRAFT7']).DRAFT7)
    registry=registry.with_resource(f.resolve().as_uri(),resource)
    registry=registry.with_resource(f.name,resource)
    if obj.get('$id'): registry=registry.with_resource(obj['$id'],resource)
base=a.schema_dir/'extension.schema.json'; schema=json.loads(base.read_text()); cls=jsonschema.validators.validator_for(schema); cls.check_schema(schema); cls(schema,registry=registry).validate(yaml.safe_load(a.extension.read_text())); print('Official schema validation successful')
