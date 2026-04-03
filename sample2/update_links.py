import os
import re

out_dir = 'd:/DTI_PROJECT/sample2'

# Find all HTML files
html_files = [f for f in os.listdir(out_dir) if f.endswith('.html')]

navbar_replacements = {
    r'<a.*?href="#">Home</a>': r'<a class="text-[#bac9cc] hover:text-[#c3f5ff] transition-colors transition-all active:scale-95 duration-200 ease-in-out" href="index.html">Home</a>',
    r'<a.*?href="#">Features</a>': r'<a class="text-[#bac9cc] hover:text-[#c3f5ff] transition-colors transition-all active:scale-95 duration-200 ease-in-out" href="safecall_dashboard_3.html">Dashboard</a>',
    r'<a.*?href="#">Awareness</a>': r'<a class="text-[#bac9cc] hover:text-[#c3f5ff] transition-colors transition-all active:scale-95 duration-200 ease-in-out" href="safecall_awareness__safety_tips_5.html">Awareness</a>',
    r'<a.*?href="#">Login</a>': r'<a class="text-[#bac9cc] hover:text-[#c3f5ff] transition-colors transition-all active:scale-95 duration-200 ease-in-out" href="safecall_login_page_6.html">Login</a>',
}

for filename in html_files:
    filepath = os.path.join(out_dir, filename)
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Apply all replacements
    for pattern, replacement in navbar_replacements.items():
        content = re.sub(pattern, replacement, content)

    # Make "Get Protected" buttons go to sign up page
    get_protected_pattern = r'<button class="bg-\[#00e5ff\] text-\[#00363d\].*?>\s*Get Protected\s*</button>'
    get_protected_replacement = r'<a href="safecall_sign_up_page_0.html" class="bg-[#00e5ff] text-[#00363d] px-6 py-2 rounded-md font-bold transition-all hover:bg-[#c3f5ff] active:scale-95 duration-200 shadow-[0_0_12px_rgba(0,229,255,0.3)]">Get Protected</a>'
    content = re.sub(get_protected_pattern, get_protected_replacement, content, flags=re.DOTALL)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

print("Updated links in all HTML files.")
