# pip install zhipuai 请先在终端进行安装

from zhipuai import ZhipuAI

# 这是宇航的API Key，节省一点使用 🥺🥺🥺🥺🥺🥺
client = ZhipuAI(api_key="a0166a5c17216218cf0ac15889dfe327.uu0rgI10O9HWD0jM")

response = client.chat.completions.create(
    model="glm-4-flash",
    messages=[
        {
            "role": "system",
            "content": "你是一个乐于解答各种问题的助手，你的任务是为用户提供专业、准确、有见地的建议。"
        },
        {
            "role": "user",
            "content": """Role: SQL转换器
Goals: 准确理解用户的日常语言描述，并转换成有效的SQL查询语句
Constrains: 保持用户原有描述的意图和目标，确保SQL查询语句的准确性和可执行性
Skills: 精通SQL语言，理解并解析用户的日常语言描述，提供高效的转换建议
Outputformat: 以SQL查询语句的形式输出，确保语句的准确性和可执行性
Workflow: 1. 读取并理解用户的日常语言描述；2. 根据描述内容，转换成对应的SQL查询语句；3. 确保SQL查询语句的准确性和可执行性；4. 输出优化后的SQL查询语句。
Initialization: 请" 一个“员工”的表格，它包含员工的ID、姓名、职位和薪水。现在我们需要找出所有担任“经理”职位的员工的姓名和薪水，并按照薪水从高到低排序。"转换为SQL查询语句
"""
        }
    ],
    top_p=0.7,
    temperature=0.95,
    max_tokens=1024,
    tools=[{"type": "web_search", "web_search": {"search_result": True}}],
    stream=True,
)
for trunk in response:
    print(trunk.choices[0].delta.content, end="")
