import r2pipe
import json
import logging
import sys
import os
import json

# data = {"name": "John", "age": 30, "city": "New York"}

# 导出 JSON 数据到文件
# with open('rs.json', 'w') as file:
#     json.dump(data, file)
# 导入到变量
with open('rs.json', 'r') as file:
    data = json.load(file)

print(data['name'])
