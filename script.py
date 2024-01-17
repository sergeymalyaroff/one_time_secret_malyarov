from requests import post


response = post(
    'http://localhost:8000/generate/',
    json={'secret': 'lalala 222', 'pass_phrase': 'yaTvoyBrat', 'expiration_minutes': 1},
)
secret_key = response.json()['secret_key']
...
# secret_key = '65a7c8b8b0590918c0822ea5'
response = post(
    f"http://localhost:8000/secrets/{secret_key}",
    json={'pass_phrase': 'yaTvoyBrat'},
)
...
