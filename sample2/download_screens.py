import json
import urllib.request
import os

data_path = 'C:/Users/likhi/.gemini/antigravity/brain/e8bb77f7-c9e6-4cf8-a948-68a9bfc239e8/.system_generated/steps/6/output.txt'
out_dir = 'd:/DTI_PROJECT/sample2'
os.makedirs(out_dir, exist_ok=True)

with open(data_path, 'r', encoding='utf-8') as f:
    data = json.load(f)

for idx, screen in enumerate(data.get('screens', [])):
    title = screen.get('title', f'Screen_{idx}')
    url = screen.get('htmlCode', {}).get('downloadUrl')
    if url:
        safe_title = "".join(x for x in title if x.isalnum() or x in " -_")
        safe_title = safe_title.replace(' ', '_').lower()
        if screen.get('deviceType') == 'MOBILE':
            safe_title += '_mobile'
        
        filepath = os.path.join(out_dir, f"{safe_title}_{idx}.html")
        print(f"Downloading {title} to {filepath}")
        
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                content = response.read()
            with open(filepath, 'wb') as out_f:
                out_f.write(content)
        except Exception as e:
            print(f"Failed to download {title}: {e}")
