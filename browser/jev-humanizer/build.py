from pathlib import Path
import json, shutil, zipfile
ROOT=Path(__file__).resolve().parent
for browser in ('chrome','firefox'):
 target=ROOT/'dist'/browser
 if target.exists():shutil.rmtree(target)
 shutil.copytree(ROOT/'src',target)
 base={"name":"Jev Humanizer","version":"0.1.0","description":"Local English editing suggestions with optional Jev meaning and tone checks.","icons":{"48":"icon48.png","128":"icon128.png"}}
 action={"default_popup":"popup.html","default_title":"Jev Humanizer","default_icon":{"48":"icon48.png","128":"icon128.png"}}
 csp="script-src 'self'; object-src 'none'; connect-src https://api.typesafe.ai; base-uri 'none'; frame-src 'none'"
 if browser=='chrome':
  base.update(manifest_version=3,minimum_chrome_version='120',action=action,permissions=['activeTab','scripting','clipboardWrite'],host_permissions=['https://api.typesafe.ai/*'],content_security_policy={'extension_pages':csp})
 else:
  base.update(manifest_version=2,browser_action=action,permissions=['activeTab','clipboardWrite','https://api.typesafe.ai/*'],content_security_policy=csp,browser_specific_settings={'gecko':{'id':'jev-humanizer@newuser7171','strict_min_version':'140.0','data_collection_permissions':{'required':['authenticationInfo','websiteContent','personalCommunications']}},'gecko_android':{'strict_min_version':'140.0'}})
 (target/'manifest.json').write_text(json.dumps(base,indent=2)+'\n')
 with zipfile.ZipFile(ROOT/'dist'/f'Jev-Humanizer-{browser}.zip','w',zipfile.ZIP_DEFLATED) as z:
  for file in sorted(target.iterdir()):z.write(file,file.name)
 print(target)
