import openai
from tiktoken import TiktokenCounter

# Thay thế 'YOUR_API_KEY' bằng API key của bạn
openai.api_key = 'YOUR_API_KEY'

# Text cần đếm số lượng tokens
text = "This is a sample text for token counting."

# Tạo một instance của TiktokenCounter
counter = TiktokenCounter()

# Đếm số lượng tokens
counter.count(text)

# Lấy số lượng tokens
token_count = counter.get_token_count()

# In thông tin về số lượng tokens
print(f"Tổng số tokens: {token_count}")
