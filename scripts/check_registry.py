import json
path = '/opt/ha-config/.storage/core.entity_registry'
data = json.load(open(path))
entries = [e for e in data['data']['entities'] if e.get('platform') == 'openwrt_router']
print(len(entries), 'entities')
for e in sorted(entries, key=lambda x: x['entity_id']):
    print(e['entity_id'], '|', e['unique_id'][:60])
