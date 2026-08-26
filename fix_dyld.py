import urllib.request

url = "https://raw.githubusercontent.com/opa334/ChOma/main/src/DyldSharedCache.c"
upstream = urllib.request.urlopen(url, timeout=30).read().decode('utf-8')

# Find and replace dsc_image_enumerate_patches with stub
old_start = "int dsc_image_enumerate_patches(DyldSharedCache *sharedCache, DyldSharedCacheImage *image, void (^enumeratorBlock)(unsigned v, void *patchable_location, bool *stop))"

# The function starts at old_start and ends at the closing brace + newline before the next function
stub = """int dsc_image_enumerate_patches(DyldSharedCache *sharedCache, DyldSharedCacheImage *image, void (^enumeratorBlock)(unsigned v, void *patchable_location, bool *stop))
{
    // Stub: dyld_cache_patch_info_v3 struct not available in this dyld_cache_format.h version
    return -1;
}"""

# Find the function start
start_idx = upstream.find(old_start)
if start_idx == -1:
    print("ERROR: could not find function start")
    exit(1)

# Find the next function definition after this one
rest = upstream[start_idx + len(old_start):]
# Find the closing brace that ends this function, then skip to next function
# Look for "\nint " which signals the next top-level function
curly_depth = 0
pos = start_idx + len(old_start)
in_body = False
while pos < len(upstream):
    ch = upstream[pos]
    if ch == '{':
        curly_depth += 1
        in_body = True
    elif ch == '}':
        curly_depth -= 1
        if in_body and curly_depth == 0:
            # Found the end of this function, include the trailing newline
            end_pos = pos + 1
            # Skip trailing newlines/spaces until next function or end
            while end_pos < len(upstream) and upstream[end_pos] in '\n\r \t':
                end_pos += 1
            break
    pos += 1
else:
    print("ERROR: could not find function end")
    exit(1)

new_source = upstream[:start_idx] + stub + "\n\n" + upstream[end_pos:]

out_path = r"C:\Users\gukyfi\Desktop\苹果吸附软件\kflog_app_update\choma\DyldSharedCache.c"
with open(out_path, 'w', encoding='utf-8') as f:
    f.write(new_source)

print("OK: written", out_path)
print("Total lines:", new_source.count('\n'))

# Verify around line 636
lines = new_source.split('\n')
for i, line in enumerate(lines[630:645], start=631):
    print(f"{i}: {line}")
