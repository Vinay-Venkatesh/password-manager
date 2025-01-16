from shutil import disk_usage

import psutil

# Get the memory usage in bytes
memory_info = psutil.virtual_memory()
disk_usage = psutil.disk_usage("/")

disk_percent_used = disk_usage.percent
total_memory = memory_info.total
used_memory = memory_info.used
percent_used = memory_info.percent

print(f"Total memory: {total_memory / (1024 ** 3):.2f} GB")
print(f"Used memory: {used_memory / (1024 ** 3):.2f} GB")
print(f"Percentage used: {percent_used}%")
print(f"Disk used Percentage: {disk_percent_used}%")