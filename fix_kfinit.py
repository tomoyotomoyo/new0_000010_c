with open(r'C:\Users\gukyfi\Desktop\苹果吸附软件\kflog_app_update\KFInit.c', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Fix: remove duplicate "Module 1" blocks and duplicate function starts
seen_module1 = False
seen_kfinit = False
cleaned = []
i = 0
while i < len(lines):
    line = lines[i]
    stripped = line.strip()
    
    if stripped == '// ===== Module 1: Initialization =====':
        if seen_module1:
            # Skip this line and any following blank lines until we hit int KFInit
            i += 1
            while i < len(lines) and lines[i].strip() == '':
                i += 1
            if i < len(lines) and 'int KFInit(void)' in lines[i]:
                i += 1  # skip the duplicate int KFInit
                while i < len(lines) and lines[i].strip() == '':
                    i += 1
            continue
        seen_module1 = True
    
    if stripped == 'int KFInit(void) {' and seen_kfinit:
        # Skip duplicate function start and following blank lines
        i += 1
        while i < len(lines) and lines[i].strip() == '':
            i += 1
        continue
    
    if stripped == 'int KFInit(void) {':
        seen_kfinit = True
    
    cleaned.append(line)
    i += 1

with open(r'C:\Users\gukyfi\Desktop\苹果吸附软件\kflog_app_update\KFInit.c', 'w', encoding='utf-8') as f:
    f.writelines(cleaned)

print("OK")
