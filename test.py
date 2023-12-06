import openai

openai.api_key = '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'  # Replace with your OpenAI API key

def count_tokens(prompt):
    try:
        # Use the `openai.Completion.create` method to count tokens
        response = openai.chat.completions.create(
            engine="gpt-3.5-turbo",  # You can adjust the engine
            prompt=prompt,
            max_tokens=0  # Setting max_tokens to 0 returns only the token count
        )

        # Extract the token count from the API response
        tokens_used = response['usage']['total_tokens']

        return tokens_used

    except Exception as e:
        print(f"Error counting tokens: {e}")
        return None

# Your user prompt
user_prompt = "Translate the following English text to French: "

# Check the number of tokens
tokens_used = count_tokens(user_prompt)

if tokens_used is not None:
    print(f"Total tokens used: {tokens_used}")
