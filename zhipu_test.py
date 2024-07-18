# pip install zhipuai 请先在终端进行安装

from zhipuai import ZhipuAI

# 这是宇航的API Key，节省一点使用 🥺🥺🥺🥺🥺🥺
client = ZhipuAI(api_key="a0166a5c17216218cf0ac15889dfe327.uu0rgI10O9HWD0jM")

response = client.chat.completions.create(
    model="glm-4-flash",
    messages=[
        {
            "role": "system",
            "content": "你是一个软件分析专家，请参考下面的分析内容猜测这个软件是否有害， 你的回答不能有“无法确定 XXX APP 是否有害”的说法，也不要回答“结合其他安全工具或平台对  APP 进行更全面的安全评估。”，相信你的判断"
        },
        {
            "role": "user",
            "content": """
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
