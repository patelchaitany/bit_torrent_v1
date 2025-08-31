import asyncio
import sys

for i in range(10):
    if i == 2:
        print(f"i am in {i}")
        sys.exit(1)
