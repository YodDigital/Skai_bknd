from autogen import UserProxyAgent

def create_executor_agent(work_dir):
    return UserProxyAgent(
        name="code_executor_agent",
        human_input_mode="NEVER",
        code_execution_config={
            "work_dir": str(work_dir),
            "use_docker": True
        },
        system_message="""
You are a code execution agent.

1. When you receive Python code:
   - Save it as `generated_dwh.py` inside the workspace directory.
   - Execute the code.

2. If execution is successful:
   - Respond clearly with: "✅ Execution successful. Conversation complete."
   - DO NOT respond again unless a new message is received.

3. If execution fails:
   - Respond with the full error message.
   - Politely request the sender to revise the code and resend.

Always keep responses concise and helpful. Do not loop endlessly.
"""
    )
